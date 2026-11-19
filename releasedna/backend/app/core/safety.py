"""Bounded, allowlisted retrieval and non-extracting archive inspection."""
import hashlib
import io
import re
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urljoin

import httpx

MAX_DOWNLOAD = 24 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_FILES = 6000
HOSTS = {'registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org',
         'api.github.com', 'codeload.github.com', 'github.com'}


class InspectionError(ValueError):
    pass


def validate_url(url):
    p = urlsplit(url)
    if (p.scheme != 'https' or p.hostname not in HOSTS or p.port not in (None, 443)
            or p.username or p.password or p.fragment):
        raise InspectionError('URL must use HTTPS on an approved registry/source host')
    if p.hostname == 'github.com' and (not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git/info/refs', p.path)
                                      or p.query != 'service=git-upload-pack'):
        raise InspectionError('Only public Git reference discovery is allowed on github.com')
    return url


class Fetcher:
    def __init__(self):
        self.deadline = time.monotonic() + 120
        self.client = httpx.Client(timeout=15, follow_redirects=False, trust_env=False,
                                   headers={'User-Agent': 'ReleaseDNA/0.1', 'Accept-Encoding': 'identity'})

    def close(self):
        self.client.close()

    def get(self, url, limit=MAX_DOWNLOAD):
        for _ in range(4):
            validate_url(url)
            if time.monotonic() > self.deadline:
                raise InspectionError('Scan network time budget exhausted')
            with self.client.stream('GET', url) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    url = urljoin(url, response.headers.get('location', ''))
                    continue
                response.raise_for_status()
                chunks, total = [], 0
                for chunk in response.iter_bytes(65536):
                    total += len(chunk)
                    if total > limit or time.monotonic() > self.deadline:
                        raise InspectionError('Download size/time limit exceeded')
                    chunks.append(chunk)
                return b''.join(chunks)
        raise InspectionError('Redirect limit exceeded')

    def json(self, url):
        import json
        return json.loads(self.get(url, 8 * 1024 * 1024))


@dataclass(frozen=True)
class File:
    data: bytes
    executable: bool = False

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()


def safe_path(name):
    if (not name or len(name) > 512 or '\\' in name or ':' in name
            or name.startswith('/') or any(ord(c) < 32 for c in name)
            or '..' in name.split('/')):
        raise InspectionError('Unsafe archive path: ' + repr(name[:100]))
    p = str(PurePosixPath(name))
    if p == '.':
        raise InspectionError('Empty archive path')
    return p


def inspect_archive(blob, strip_root=True):
    """No writes to disk. Reject links, devices, ambiguous paths and expansion bombs."""
    if len(blob) > MAX_DOWNLOAD:
        raise InspectionError('Compressed archive exceeds limit')
    files, seen, total = {}, set(), 0
    started = time.monotonic()

    def add(name, size, mode, read):
        nonlocal total
        name = safe_path(name)
        if name.casefold() in seen:
            raise InspectionError('Duplicate or case-colliding archive path')
        seen.add(name.casefold())
        total += size
        if size > MAX_FILE or total > MAX_EXPANDED or len(seen) > MAX_FILES:
            raise InspectionError('Archive inspection limits exceeded')
        if time.monotonic() - started > 15:
            raise InspectionError('Archive inspection time limit exceeded')
        data = read(MAX_FILE + 1)
        if len(data) != size:
            raise InspectionError('Archive member size mismatch')
        files[name] = File(data, bool(mode & 0o111))

    try:
        if zipfile.is_zipfile(io.BytesIO(blob)):
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                if len(archive.infolist()) > MAX_FILES:
                    raise InspectionError('Too many archive entries')
                for member in archive.infolist():
                    safe_path(member.filename)
                    mode = member.external_attr >> 16
                    if mode & 0o170000 not in (0, 0o100000, 0o040000):
                        raise InspectionError('Links and special entries are forbidden')
                    if not member.is_dir():
                        with archive.open(member) as stream:
                            add(member.filename, member.file_size, mode, stream.read)
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode='r|*') as archive:
                for index, member in enumerate(archive):
                    if index >= MAX_FILES:
                        raise InspectionError('Too many archive entries')
                    safe_path(member.name)
                    if member.isdir():
                        continue
                    if not member.isfile() or member.issparse():
                        raise InspectionError('Links, sparse and special entries are forbidden')
                    with archive.extractfile(member) as stream:
                        add(member.name, member.size, member.mode, stream.read)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise InspectionError('Invalid or damaged archive') from exc
    if not files:
        raise InspectionError('Empty archive')
    if strip_root:
        roots = {p.split('/')[0] for p in files}
        if len(roots) != 1 or any('/' not in p for p in files):
            raise InspectionError('Expected one archive root directory')
        files = {p.split('/', 1)[1]: f for p, f in files.items()}
    return files
