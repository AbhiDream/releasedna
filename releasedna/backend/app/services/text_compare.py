"""A bounded pair of UTF-8 files; contents remain untrusted data."""
import hashlib
import time
from datetime import datetime, timezone
from app.core.safety import File, InspectionError, safe_path
from app.diff_engine.compare import compare

MAX_TEXT = 120000


def compare_text_files(artifact, source, name='comparison.txt'):
    started = time.monotonic()
    name = safe_path(name)
    if '/' in name:
        raise InspectionError('Text comparison needs a filename, not a directory path')
    for data in (artifact, source):
        if len(data) > MAX_TEXT:
            raise InspectionError('Text files must be at most 120000 bytes each')
        try:
            value = data.decode('utf-8')
        except UnicodeError as exc:
            raise InspectionError('Text comparison accepts UTF-8 only; use archives for binary data') from exc
        if '\x00' in value:
            raise InspectionError('NUL bytes are not accepted in text comparison')
    result = compare({name: File(artifact)}, {name: File(source)}, False)
    result.update(engine_version='0.2.0', created_at=datetime.now(timezone.utc).isoformat(),
                  package={'ecosystem': 'text', 'name': name, 'version': 'supplied files'},
                  artifact={'digest': 'sha256:' + hashlib.sha256(artifact).hexdigest(), 'verified': False, 'origin': 'user_supplied'},
                  source={'confidence': 'user_supplied', 'identity_corroborated': False, 'build_provenance_verified': False,
                          'sha256': hashlib.sha256(source).hexdigest(), 'reasons': ['A supplied text pair has no independently verified package/source identity.']},
                  publication=None, error=None, duration_seconds=round(time.monotonic()-started, 3))
    result['limitations'].append('Direct UTF-8 text comparison, not a complete package scan. Both original byte hashes are retained. Text is never executed or treated as instructions.')
    return result
