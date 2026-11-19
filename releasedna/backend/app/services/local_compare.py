"""Compare supplied archives as data. User-supplied hashes are not registry provenance."""
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from app.core.safety import inspect_archive, safe_path, InspectionError, MAX_DOWNLOAD
from app.diff_engine.compare import compare


def archive_files(blob, layout='auto', prefix=''):
    files=inspect_archive(blob,strip_root=False)
    if layout not in {'auto','strip','keep'}: raise InspectionError('Invalid archive layout')
    roots={p.split('/')[0] for p in files}
    single=len(roots)==1 and all('/' in p for p in files)
    if layout=='strip' and not single: raise InspectionError('Archive has no single wrapper directory')
    # Wheels normally have package + dist-info siblings. Tar releases have a wrapper.
    wheel=any('.dist-info/' in p for p in files)
    stripped=single and (layout=='strip' or (layout=='auto' and not wheel))
    if stripped: files={p.split('/',1)[1]:f for p,f in files.items()}
    if prefix:
        prefix=safe_path(prefix).rstrip('/')+'/'
        files={p[len(prefix):]:f for p,f in files.items() if p.startswith(prefix)}
        if not files: raise InspectionError('Selected archive prefix has no files')
    return files,{'layout':layout,'wrapper_stripped':stripped,'selected_prefix':prefix}


def compare_archives(artifact,source,name='local comparison',artifact_layout='auto',source_layout='auto',artifact_prefix='',source_prefix=''):
    started=time.monotonic()
    a,al=archive_files(artifact,artifact_layout,artifact_prefix)
    s,sl=archive_files(source,source_layout,source_prefix)
    result=compare(a,s,False)
    result.update(engine_version='0.2.0',created_at=datetime.now(timezone.utc).isoformat(),
                  package={'ecosystem':'local','name':name,'version':'supplied archives'},
                  artifact={'digest':'sha256:'+hashlib.sha256(artifact).hexdigest(),'verified':False,'origin':'user_supplied'},
                  source={'confidence':'user_supplied','identity_corroborated':False,'build_provenance_verified':False,'archive_sha256':hashlib.sha256(source).hexdigest(),'reasons':['Source identity is supplied by the user, not independently matched to an official release.']},
                  archive_layouts={'artifact':al,'source':sl},publication=None,error=None,
                  duration_seconds=round(time.monotonic()-started,3))
    result['limitations'].append('Local archive comparison: no official registry integrity or repository identity verification. ZIP/wheel and tar inputs are read without extraction or execution.')
    return result


def read_bounded(path):
    with Path(path).open('rb') as stream:
        data=stream.read(MAX_DOWNLOAD+1)
    if len(data)>MAX_DOWNLOAD: raise InspectionError('Archive exceeds 24 MiB compressed limit')
    return data
