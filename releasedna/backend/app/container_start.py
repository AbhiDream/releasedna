"""Container entrypoint, not a host development launcher."""
import os
from pathlib import Path
import tempfile


def main():
    if os.name != 'posix' or os.geteuid() == 0:
        raise RuntimeError('Run this image as its non-root Linux user; do not launch the container entrypoint on the host')
    if len(os.environ.get('RELEASEDNA_API_TOKEN', '')) < 32:
        raise RuntimeError('Set RELEASEDNA_API_TOKEN to a random value of at least 32 characters')
    os.environ['RELEASEDNA_REQUIRE_AUTH'] = '1'
    data = Path(os.environ.get('RELEASEDNA_DB', '/app/data/scans.sqlite3'))
    data.parent.mkdir(parents=True, exist_ok=True)
    # Fail clearly if a provider volume overrides the image's writable mount permissions.
    with tempfile.TemporaryFile(dir=data.parent) as probe:
        probe.write(b'volume write check')
    port = int(os.environ.get('PORT', '8000'))
    if not 1024 <= port <= 65535:
        raise ValueError('PORT must be between 1024 and 65535')
    import uvicorn
    uvicorn.run('app.api.main:app', host='0.0.0.0', port=port, workers=1, timeout_graceful_shutdown=160)


if __name__ == '__main__':
    main()
