import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.core.safety import InspectionError
from app.connectors.registry import validate_input
from app.services.jobs import JobStore, Worker, QueueFull
from app.services.scan import scan
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


def create_app(db_path=None, scanner=scan, monitor_poller=None):
    @asynccontextmanager
    async def lifespan(application):
        store = JobStore(db_path or os.environ.get('RELEASEDNA_DB', str(ROOT / 'data' / 'scans.sqlite3')))
        worker = Worker(store, scanner)
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

    application = FastAPI(title='ReleaseDNA', version='0.1.3', lifespan=lifespan,
                          description='Durable package/source inspection jobs. CLEAN: No suspicious differences detected within the available analysis scope.')

    @application.get('/health')
    def health():
        return {'status': 'ok', 'engine': '0.1.3', 'worker_alive': application.state.worker.thread.is_alive(), 'monitor_alive': application.state.monitor.thread.is_alive()}

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
