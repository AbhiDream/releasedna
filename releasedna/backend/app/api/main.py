import threading
from typing import Literal
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from app.core.safety import InspectionError
from app.services.scan import scan

app = FastAPI(title='ReleaseDNA', version='0.1.0', description='Read-only package/source forensics. No fetched code is executed.')
slot = threading.BoundedSemaphore(1)


class ScanRequest(BaseModel):
    ecosystem: Literal['npm', 'pypi']
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=80)


@app.get('/health')
def health():
    return {'status': 'ok', 'engine': '0.1.0'}


@app.post('/api/scans')
def create_scan(request: ScanRequest):
    if not slot.acquire(blocking=False):
        raise HTTPException(429, 'One scan is already running; retry after it completes')
    try:
        return scan(request.ecosystem, request.name, request.version)
    except InspectionError as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        slot.release()
