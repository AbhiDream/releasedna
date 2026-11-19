"""Single-worker durable SQLite queue. One process may own a database at a time."""
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager


def now():
    return datetime.now(timezone.utc).isoformat()


class QueueFull(ValueError):
    pass


class JobStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, state TEXT NOT NULL, request TEXT NOT NULL,
                created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                result TEXT, error TEXT)''')
            db.execute('CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,label TEXT,body BLOB,created_at TEXT)')

    def upload(self,label,body):
        from app.core.safety import MAX_DOWNLOAD
        if not body or len(body)>MAX_DOWNLOAD: raise ValueError('Archive must contain 1 byte to 24 MiB')
        identity=str(uuid.uuid4())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # Bound retained uploads. A caller can explicitly remove unused inputs.
            total=db.execute('SELECT coalesce(sum(length(body)),0) FROM uploads').fetchone()[0]
            if total+len(body)>256*1024*1024: raise QueueFull('Local archive storage full (256 MiB); remove unused uploads')
            db.execute('INSERT INTO uploads VALUES (?,?,?,?)',(identity,label[:160],body,now()))
        return {'id':identity,'bytes':len(body),'label':label[:160]}

    def read_upload(self,identity):
        with self.connect() as db:
            row=db.execute('SELECT body FROM uploads WHERE id=?',(identity,)).fetchone()
            if not row: raise ValueError('Upload not found')
            return bytes(row['body'])

    def remove_upload(self,identity):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT request FROM scans WHERE state IN ('queued','running')"):
                request=json.loads(row['request'])
                if identity in (request.get('artifact_id'),request.get('source_id')):
                    raise ValueError('Upload is referenced by an active comparison')
            db.execute('DELETE FROM uploads WHERE id=?',(identity,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def decode(row, include_result=True):
        if row is None:
            return None
        item = dict(row)
        item['package'] = json.loads(item.pop('request'))
        if include_result:
            item['result'] = json.loads(item['result']) if item['result'] else None
        else:
            item.pop('result', None)
        return item

    def create(self, request):
        identity = str(uuid.uuid4())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if request.get('kind') == 'local':
                for key in ('artifact_id','source_id'):
                    if not db.execute('SELECT 1 FROM uploads WHERE id=?',(request[key],)).fetchone():
                        raise ValueError('Upload not found: '+key)
            if db.execute("SELECT count(*) FROM scans WHERE state IN ('queued','running')").fetchone()[0] >= 20:
                raise QueueFull('Queue is full (20 pending jobs); try again after a job finishes')
            db.execute('INSERT INTO scans(id,state,request,created_at) VALUES (?,?,?,?)',
                       (identity, 'queued', json.dumps(request), now()))
        return self.get(identity)

    def get(self, identity):
        with self.connect() as db:
            return self.decode(db.execute('SELECT * FROM scans WHERE id=?', (identity,)).fetchone())

    def history(self, limit=50, offset=0):
        with self.connect() as db:
            rows = db.execute('SELECT id,state,request,created_at,started_at,finished_at,error FROM scans ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
            total = db.execute('SELECT count(*) FROM scans').fetchone()[0]
        return {'items': [self.decode(row, False) for row in rows], 'total': total, 'limit': limit, 'offset': offset}

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE scans SET state='failed',finished_at=?,error=? WHERE state='running'",
                       (now(), 'Interrupted by backend shutdown/restart before a result was committed. Submit a new scan to retry.'))

    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM scans WHERE state='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE scans SET state='running',started_at=? WHERE id=? AND state='queued'", (now(), row['id']))
        return self.get(row['id'])

    def finish(self, identity, result=None, error=None):
        if result is not None:
            result['scan_id'] = identity
            error = error or result.get('error')
        with self.connect() as db:
            db.execute("UPDATE scans SET state=?,finished_at=?,result=?,error=? WHERE id=? AND state='running'",
                       ('failed' if error else 'completed', now(), json.dumps(result) if result is not None else None, error, identity))


class Worker:
    def __init__(self, store, scanner):
        self.store, self.scanner = store, scanner
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.lock = None

    def start(self):
        self.lock = open(str(self.store.path) + '.lock', 'a+b')
        self.lock.seek(0)
        self.lock.write(b'0')
        self.lock.flush()
        self.lock.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            raise RuntimeError('This scan database already has a worker; run one API process per database') from exc
        self.store.recover()
        self.thread = threading.Thread(target=self.run, name='releasedna-scanner', daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            job = self.store.claim()
            if job is None:
                self.wake.wait(0.5)
                self.wake.clear()
                continue
            try:
                self.store.finish(job['id'], self.scanner(**job['package']))
            except Exception as exc:
                self.store.finish(job['id'], error=f'{type(exc).__name__}: {exc}')

    def close(self):
        self.stop_event.set()
        self.wake.set()
        if self.thread:
            self.thread.join()
        if self.lock:
            self.lock.close()
