"""Durable registry polling. Notifications remain in this local SQLite database."""
import json
import threading
import time
import uuid
from urllib.parse import quote
import httpx
from app.connectors.registry import validate_input
from app.services.jobs import now


def registry_poll(ecosystem, name, etag):
    url = ('https://registry.npmjs.org/'+quote(name,safe='') if ecosystem=='npm'
           else 'https://pypi.org/pypi/'+quote(name,safe='')+'/json')
    headers={'User-Agent':'ReleaseDNA/0.1.3','Accept-Encoding':'identity'}
    if etag:
        headers['If-None-Match']=etag
    with httpx.Client(timeout=15,trust_env=False,follow_redirects=False) as client:
        with client.stream('GET',url,headers=headers) as response:
            if response.status_code==304:
                return 304,etag,[]
            response.raise_for_status()
            data=bytearray()
            deadline=time.monotonic()+30
            for chunk in response.iter_bytes(65536):
                data.extend(chunk)
                if len(data)>8*1024*1024 or time.monotonic()>deadline:
                    raise ValueError('Registry metadata exceeds polling size/time limit')
            meta=json.loads(data)
            identity=meta.get('name') if ecosystem=='npm' else meta.get('info',{}).get('name')
            import re
            normalize=lambda s: re.sub('[-_.]+','-',str(s)).lower()
            if (identity!=name if ecosystem=='npm' else normalize(identity)!=normalize(name)):
                raise ValueError('Registry identity mismatch')
            releases=meta.get('versions' if ecosystem=='npm' else 'releases')
            if not isinstance(releases,dict):
                raise ValueError('Registry release list is missing')
            versions=[]
            for version in releases:
                validate_input(ecosystem,name,version)
                versions.append(version)
            return 200,response.headers.get('etag'),versions


class ReleaseMonitor:
    def __init__(self,store,worker,poller=registry_poll):
        self.store,self.worker,self.poller=store,worker,poller
        self.stop=threading.Event()
        self.wake=threading.Event()
        self.guard=threading.Lock()
        with store.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS watches(id TEXT PRIMARY KEY,ecosystem TEXT,name TEXT,
              etag TEXT,initialized INTEGER DEFAULT 0,last_checked TEXT,error TEXT,
              next_poll REAL DEFAULT 0,UNIQUE(ecosystem,name));
            CREATE TABLE IF NOT EXISTS observed(watch_id TEXT,version TEXT,
              PRIMARY KEY(watch_id,version));
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,watch_id TEXT,scan_id TEXT,
              kind TEXT,message TEXT,created_at TEXT,read INTEGER DEFAULT 0,
              UNIQUE(scan_id,kind));
            ''')
        self.thread=threading.Thread(target=self.run,daemon=True,name='releasedna-monitor')

    def add(self,ecosystem,name):
        validate_input(ecosystem,name,'1.0.0')
        identity=str(uuid.uuid4())
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing=db.execute('SELECT id FROM watches WHERE ecosystem=? AND name=?',(ecosystem,name)).fetchone()
            if existing: return existing['id']
            if db.execute('SELECT count(*) FROM watches').fetchone()[0]>=50:
                raise ValueError('Maximum 50 watched packages')
            db.execute('INSERT INTO watches(id,ecosystem,name) VALUES (?,?,?)',(identity,ecosystem,name))
        self.wake.set()
        return identity

    def remove(self,identity):
        with self.store.connect() as db:
            db.execute('DELETE FROM watches WHERE id=?',(identity,))
            db.execute('DELETE FROM observed WHERE watch_id=?',(identity,))

    def snapshot(self):
        with self.store.connect() as db:
            return {'watches':[dict(r) for r in db.execute('SELECT * FROM watches ORDER BY name')],
                    'alerts':[dict(r) for r in db.execute('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100')]}

    def tick(self,force=False):
        if not self.guard.acquire(blocking=False): return
        try:
            with self.store.connect() as db:
                watches=[dict(r) for r in db.execute('SELECT * FROM watches WHERE next_poll<=? ORDER BY next_poll LIMIT 10',(float('inf') if force else time.time(),))]
            for watch in watches:
                if self.stop.is_set(): break
                try:
                    code,etag,versions=self.poller(watch['ecosystem'],watch['name'],watch['etag'])
                    if code not in (200,304) or (code==304 and not watch['initialized']):
                        raise ValueError('Unexpected registry polling response')
                    with self.store.connect() as db:
                        db.execute('BEGIN IMMEDIATE')
                        if not db.execute('SELECT id FROM watches WHERE id=?',(watch['id'],)).fetchone(): continue
                        capacity=20-db.execute("SELECT count(*) FROM scans WHERE state IN ('queued','running')").fetchone()[0]
                        pending=False
                        if code==200:
                            seen={r[0] for r in db.execute('SELECT version FROM observed WHERE watch_id=?',(watch['id'],))}
                            for version in sorted(set(versions)-seen):
                                validate_input(watch['ecosystem'],watch['name'],version)
                                if watch['initialized']:
                                    if capacity<=0:
                                        pending=True
                                        continue
                                    identity=str(uuid.uuid4())
                                    request={'ecosystem':watch['ecosystem'],'name':watch['name'],'version':version}
                                    db.execute('INSERT INTO scans(id,state,request,created_at) VALUES (?,?,?,?)',(identity,'queued',json.dumps(request),now()))
                                    db.execute('INSERT INTO alerts(id,watch_id,scan_id,kind,message,created_at) VALUES (?,?,?,?,?,?)',(str(uuid.uuid4()),watch['id'],identity,'new_release',f"New release {watch['name']}@{version}; scan queued",now()))
                                    capacity-=1
                                db.execute('INSERT OR IGNORE INTO observed VALUES (?,?)',(watch['id'],version))
                        db.execute('UPDATE watches SET initialized=1,etag=?,last_checked=?,error=?,next_poll=? WHERE id=?',
                                   (None if pending else etag,now(),'Queue full; unseen releases will be retried' if pending else None,time.time()+300,watch['id']))
                    self.worker.wake.set()
                except Exception as exc:
                    with self.store.connect() as db:
                        db.execute('UPDATE watches SET error=?,last_checked=?,next_poll=? WHERE id=?',(f'{type(exc).__name__}: {str(exc)[:300]}',now(),time.time()+300,watch['id']))
            self.completed_alerts()
        finally:
            self.guard.release()

    def completed_alerts(self):
        with self.store.connect() as db:
            rows=db.execute("SELECT a.watch_id,s.id,s.state,s.result,s.request FROM alerts a JOIN scans s ON s.id=a.scan_id WHERE a.kind='new_release' AND s.state IN ('completed','failed') AND NOT EXISTS(SELECT 1 FROM alerts b WHERE b.scan_id=s.id AND b.kind='scan_result')").fetchall()
            for row in rows:
                report=json.loads(row['result']) if row['result'] else {}
                package=json.loads(row['request'])
                message=f"{package['name']}@{package['version']}: {row['state']} · {report.get('status','no result')} · {len(report.get('findings',[]))} findings"
                db.execute('INSERT OR IGNORE INTO alerts(id,watch_id,scan_id,kind,message,created_at) VALUES (?,?,?,?,?,?)',(str(uuid.uuid4()),row['watch_id'],row['id'],'scan_result',message,now()))

    def run(self):
        while not self.stop.is_set():
            try: self.tick()
            except Exception:
                import logging
                logging.exception('Release monitor tick failed')
            self.wake.wait(5)
            self.wake.clear()

    def close(self):
        self.stop.set(); self.wake.set()
        if self.thread.is_alive(): self.thread.join()
