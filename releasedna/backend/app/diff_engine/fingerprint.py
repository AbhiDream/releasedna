"""Stable across Git LF/CRLF checkouts; bind detector filenames and content."""
import hashlib
from pathlib import Path

FILES=('compare.py','generated.py','omissions.py','metadata.py','syntax.py','build_adapters.py','fingerprint.py','javascript_patterns.py')


def detector_fingerprint(root=None):
    root=Path(root) if root is not None else Path(__file__).parent
    digest=hashlib.sha256()
    for name in FILES:
        digest.update(name.encode()+b'\x00')
        digest.update((root/name).read_bytes().replace(b'\r\n',b'\n'))
        digest.update(b'\x00')
    return digest.hexdigest()
