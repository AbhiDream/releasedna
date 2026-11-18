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

ROOT = Path(__file__).resolve().parents[3]


class ScanRequest(BaseModel):
    ecosystem: Literal['npm', 'pypi']
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=80)


def create_app(db_path=None, scanner=scan):
    @asynccontextmanager
    async def lifespan(application):
        store = JobStore(db_path or os.environ.get('RELEASEDNA_DB', str(ROOT / 'data' / 'scans.sqlite3')))
        worker = Worker(store, scanner)
        worker.start()
        application.state.store, application.state.worker = store, worker
        try:
            yield
        finally:
            worker.close()

    application = FastAPI(title='ReleaseDNA', version='0.1.1', lifespan=lifespan,
                          description='Durable package/source inspection jobs. CLEAN: No suspicious differences detected within the available analysis scope.')

    @application.get('/health')
    def health():
        return {'status': 'ok', 'engine': '0.1.1', 'worker_alive': application.state.worker.thread.is_alive()}

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
    application.mount('/assets', StaticFiles(directory=frontend), name='assets')

    @application.get('/', include_in_schema=False)
    def home():
        return FileResponse(frontend / 'index.html')

    return application


app = create_app()
