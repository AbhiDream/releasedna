import os
import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, Query, Response, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.core.safety import InspectionError
from app.connectors.registry import validate_input
from app.services.jobs import JobStore, Worker, QueueFull
from app.services.scan import scan
from app.services.process_boundary import bounded_inspection
from app.core.safety import MAX_DOWNLOAD
from app.services.monitor import ReleaseMonitor
from app.services.explanation import explain, ExplanationUnavailable, MODEL

ROOT = Path(__file__).resolve().parents[3]


class ScanRequest(BaseModel):
    ecosystem: Literal['npm', 'pypi']
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=80)


class WatchRequest(BaseModel):
    ecosystem: Literal['npm','pypi']
    name: str = Field(min_length=1,max_length=214)


class BatchRequest(BaseModel):
    packages: list[ScanRequest] = Field(min_length=1, max_length=20)


class TextRequest(BaseModel):
    artifact_id: str = Field(min_length=36, max_length=36)
    source_id: str = Field(min_length=36, max_length=36)
    name: str = Field(default='comparison.txt', min_length=1, max_length=160)


class LocalRequest(BaseModel):
    artifact_id: str = Field(min_length=36,max_length=36)
    source_id: str = Field(min_length=36,max_length=36)
    name: str = Field(default='Local comparison',min_length=1,max_length=160)
    artifact_layout: Literal['auto','strip','keep'] = 'auto'
    source_layout: Literal['auto','strip','keep'] = 'auto'
    artifact_prefix: str = Field(default='',max_length=512)
    source_prefix: str = Field(default='',max_length=512)


def create_app(db_path=None, scanner=scan, monitor_poller=None):
    @asynccontextmanager
    async def lifespan(application):
        if os.environ.get('RELEASEDNA_REQUIRE_AUTH') == '1' and len(os.environ.get('RELEASEDNA_API_TOKEN', '')) < 32:
            raise RuntimeError('Remote deployment requires RELEASEDNA_API_TOKEN with at least 32 characters')
        store = JobStore(db_path or os.environ.get('RELEASEDNA_DB', str(ROOT / 'data' / 'scans.sqlite3')))
        def dispatch(**request):
            kind = request.pop('kind',None)
            if kind in ('local', 'text'):
                payload={k:v for k,v in request.items() if k not in ('artifact_id','source_id')}
                payload.update(artifact=store.read_upload(request['artifact_id']),source=store.read_upload(request['source_id']))
                return bounded_inspection(kind,payload)
            return bounded_inspection('registry',request) if scanner is scan else scanner(**request)
        worker = Worker(store, dispatch)
        worker.start()
        application.state.store, application.state.worker = store, worker
        monitor = ReleaseMonitor(store,worker,monitor_poller) if monitor_poller else ReleaseMonitor(store,worker)
        application.state.monitor = monitor
        monitor.thread.start()
        try:
            yield
        finally:
            monitor.close()
            worker.close()

    application = FastAPI(title='ReleaseDNA', version='0.2.0', lifespan=lifespan,
                          description='Durable package/source inspection jobs. CLEAN: No suspicious differences detected within the available analysis scope.')

    @application.middleware('http')
    async def access_control(request: Request, call_next):
        token = os.environ.get('RELEASEDNA_API_TOKEN', '')
        protected = request.url.path.startswith('/api/') or request.url.path in ('/docs', '/redoc', '/openapi.json', '/corpus', '/evaluation', '/fresh-evaluation')
        if token and protected:
            supplied = request.headers.get('Authorization', '')
            if not secrets.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
                return JSONResponse({'detail': 'Workspace access key required'}, status_code=401,
                                    headers={'WWW-Authenticate': 'Bearer', 'Cache-Control': 'no-store'})
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        if request.url.path == '/':
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if protected:
            response.headers['Cache-Control'] = 'no-store'
        return response

    @application.get('/health')
    def health():
        return {'status': 'ok', 'engine': '0.2.0', 'worker_alive': application.state.worker.thread.is_alive(), 'monitor_alive': application.state.monitor.thread.is_alive(),
                'auth_required': bool(os.environ.get('RELEASEDNA_API_TOKEN')), 'scan_concurrency': 1,
                'storage': os.environ.get('RELEASEDNA_STORAGE', 'local-filesystem'),
                'deployment': os.environ.get('RELEASEDNA_DEPLOYMENT', 'development process; not container-verified')}

    @application.get('/api/queue')
    def queue_status():
        return application.state.store.queue()

    @application.post('/api/scans/batch', status_code=202)
    def batch(request: BatchRequest):
        try:
            for package in request.packages:
                validate_input(package.ecosystem, package.name, package.version)
            jobs = application.state.store.create_many([package.model_dump() for package in request.packages])
        except QueueFull as exc:
            raise HTTPException(429, str(exc)) from exc
        except InspectionError as exc:
            raise HTTPException(422, str(exc)) from exc
        application.state.worker.wake.set()
        return {'items': jobs, 'concurrency': 1}

    @application.post('/api/text-comparisons', status_code=202)
    def text_comparison(request: TextRequest, response: Response):
        from app.core.safety import safe_path
        try:
            name = safe_path(request.name)
            if '/' in name:
                raise ValueError('Use a filename without directories')
            job = application.state.store.create({'kind': 'text', **request.model_dump()})
        except QueueFull as exc:
            raise HTTPException(429, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        response.headers['Location'] = '/api/scans/' + job['id']
        application.state.worker.wake.set()
        return job

    @application.get('/api/monitor')
    def monitor_status():
        return application.state.monitor.snapshot()

    @application.post('/api/monitor',status_code=201)
    def watch(request: WatchRequest):
        try:
            return {'id':application.state.monitor.add(request.ecosystem,request.name)}
        except ValueError as exc:
            raise HTTPException(422,str(exc)) from exc

    @application.delete('/api/monitor/{identity}',status_code=204)
    def unwatch(identity: str):
        application.state.monitor.remove(identity)
        return Response(status_code=204)

    @application.post('/api/alerts/{identity}/read')
    def acknowledge(identity: str):
        with application.state.store.connect() as db:
            db.execute('UPDATE alerts SET read=1 WHERE id=?',(identity,))
        return {'ok':True}

    @application.get('/api/explanation/config')
    def explanation_config():
        return {'configured':bool(os.environ.get('GROQ_API_KEY')),'provider':'groq','model':MODEL}

    @application.post('/api/scans/{identity}/explanation')
    def scan_explanation(identity: str):
        try:
            return explain(application.state.store,identity)
        except ExplanationUnavailable as exc:
            raise HTTPException(503,str(exc)) from exc

    @application.get('/corpus',include_in_schema=False)
    def corpus_page():
        path=ROOT/'data/adversarial.html'
        if not path.exists(): raise HTTPException(404,'Run python -m app.adversarial_corpus first')
        return FileResponse(path,media_type='text/html')

    @application.get('/api/corpus')
    def corpus_json():
        path=ROOT/'data/adversarial.json'
        if not path.exists(): raise HTTPException(404,'No corpus run has been generated')
        return FileResponse(path,media_type='application/json')

    @application.post('/api/scans', status_code=202)
    def create_scan(request: ScanRequest, response: Response):
        try:
            validate_input(request.ecosystem, request.name, request.version)
            job = application.state.store.create(request.model_dump())
        except InspectionError as exc:
            raise HTTPException(422, str(exc)) from exc
        except QueueFull as exc:
            raise HTTPException(429, str(exc)) from exc
        response.headers['Location'] = '/api/scans/' + job['id']
        application.state.worker.wake.set()
        return job

    @application.get('/api/scans')
    def history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return application.state.store.history(limit, offset)

    @application.post('/api/uploads',status_code=201)
    async def upload(request: Request, label: str = Query('archive',max_length=160)):
        body=bytearray()
        try:
            async with asyncio.timeout(30):
                async for chunk in request.stream():
                    if len(body)+len(chunk)>MAX_DOWNLOAD: raise HTTPException(413,'Archive exceeds 24 MiB')
                    body.extend(chunk)
            return application.state.store.upload(label,bytes(body))
        except TimeoutError as exc: raise HTTPException(408,'Upload timed out') from exc
        except QueueFull as exc: raise HTTPException(429,str(exc)) from exc
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc

    @application.get('/api/uploads')
    def uploads():
        with application.state.store.connect() as db:
            return {'items':[dict(r) for r in db.execute('SELECT id,label,length(body) AS bytes,created_at FROM uploads ORDER BY created_at DESC')]}

    @application.delete('/api/uploads/{identity}',status_code=204)
    def remove_upload(identity: str):
        try: application.state.store.remove_upload(identity)
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc
        return Response(status_code=204)

    @application.post('/api/comparisons',status_code=202)
    def local_comparison(request: LocalRequest,response: Response):
        try: job=application.state.store.create({'kind':'local',**request.model_dump()})
        except QueueFull as exc: raise HTTPException(429,str(exc)) from exc
        except ValueError as exc: raise HTTPException(422,str(exc)) from exc
        application.state.worker.wake.set()
        response.headers['Location']='/api/scans/'+job['id']
        return job

    @application.get('/api/scans/{identity}')
    def get_scan(identity: str):
        job = application.state.store.get(identity)
        if job is None:
            raise HTTPException(404, 'Scan not found')
        return job

    frontend = ROOT / 'frontend'

    @application.get('/evaluation', include_in_schema=False)
    def evaluation_page():
        path = ROOT / 'data/evaluation.html'
        if not path.exists():
            raise HTTPException(404, 'Run python -m app.evaluation run --include-fixtures first')
        return FileResponse(path, media_type='text/html')

    @application.get('/fresh-evaluation',include_in_schema=False)
    def fresh_evaluation_page():
        path=ROOT/'data/fresh-evaluation.html'
        if not path.exists(): raise HTTPException(404,'Fresh evaluation has not been run; see docs/submission-verification.md')
        return FileResponse(path,media_type='text/html')

    @application.get('/api/evaluation/fresh')
    def fresh_evaluation_json():
        path=ROOT/'data/fresh-evaluation.json'
        if not path.exists(): raise HTTPException(404,'Fresh evaluation has not been run')
        return FileResponse(path,media_type='application/json')

    @application.get('/api/evaluation')
    def evaluation_json():
        path = ROOT / 'data/evaluation.json'
        if not path.exists():
            raise HTTPException(404, 'No evaluation has been generated')
        return FileResponse(path, media_type='application/json', filename='releasedna-evaluation.json')
    application.mount('/assets', StaticFiles(directory=frontend), name='assets')

    @application.get('/', include_in_schema=False)
    def home():
        return FileResponse(frontend / 'index.html')

    return application


app = create_app()
