import base64
import hashlib
import hmac
import re
from datetime import datetime
import httpx
from urllib.parse import quote, urlsplit
from app.core.safety import InspectionError


def npm_publication(fetcher, name, version):
    url = f'https://registry.npmjs.org/{quote(name, safe="")}'
    result = {'publication_time': None, 'publication_time_source': url + '#time.' + version,
              'publication_time_limitation': None}
    try:
        packument = fetcher.json(url)
        if packument.get('name') != name:
            raise ValueError('Package identity mismatch in publication metadata')
        value = packument.get('time', {}).get(version)
        if not isinstance(value, str):
            raise ValueError('Official registry has no timestamp for this exact release')
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('Publication timestamp lacks timezone')
        result['publication_time'] = value
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
        result['publication_time_limitation'] = str(exc)
    return result


def validate_input(ecosystem, name, version):
    pattern = r'(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*' if ecosystem == 'npm' else r'[A-Za-z0-9][A-Za-z0-9._-]*'
    if ecosystem not in ('npm', 'pypi') or len(name) > 214 or not re.fullmatch(pattern, name):
        raise InspectionError('Invalid ecosystem or package name')
    if len(version) > 80 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]*', version):
        raise InspectionError('An explicit package version is required')


def repository(value):
    if isinstance(value, dict):
        value = value.get('url', '')
    value = str(value or '').removeprefix('git+')
    value = value.replace('git://github.com/', 'https://github.com/')
    value = value.replace('git@github.com:', 'https://github.com/')
    p = urlsplit(value)
    parts = p.path.strip('/').removesuffix('.git').split('/')
    if p.hostname != 'github.com' or len(parts) != 2 or not all(re.fullmatch(r'[\w.-]+', s) for s in parts):
        return None
    return '/'.join(parts)


def fetch_release(fetcher, ecosystem, name, version):
    validate_input(ecosystem, name, version)
    if ecosystem == 'npm':
        meta = fetcher.json(f'https://registry.npmjs.org/{quote(name, safe="")}/{quote(version)}')
        if meta.get('name') != name or meta.get('version') != version:
            raise InspectionError('Registry returned a different package identity')
        dist = meta['dist']
        integrity = dist.get('integrity', '')
        candidates = [v for v in integrity.split() if v.startswith(('sha512-', 'sha384-', 'sha256-'))]
        if not candidates:
            raise InspectionError('No supported strong artifact digest in registry metadata')
        algorithm, encoded = sorted(candidates, key=lambda v: int(v[3:6]), reverse=True)[0].split('-', 1)
        expected = base64.b64decode(encoded, validate=True).hex()
        repo = repository(meta.get('repository'))
        directory = meta.get('repository', {}).get('directory', '') if isinstance(meta.get('repository'), dict) else ''
        published = {'maintainers': meta.get('maintainers', []), 'deprecated': meta.get('deprecated'),
                     'registry': 'https://registry.npmjs.org', 'publication_time': None}
        url, git_head = dist['tarball'], meta.get('gitHead')
    else:
        meta = fetcher.json(f'https://pypi.org/pypi/{quote(name)}/{quote(version)}/json')
        normalize = lambda s: re.sub(r'[-_.]+', '-', s).lower()
        if normalize(meta['info']['name']) != normalize(name) or meta['info']['version'] != version:
            raise InspectionError('Registry returned a different package identity')
        distributions = [v for v in meta['urls'] if v['packagetype'] == 'sdist']
        if len(distributions) != 1:
            raise InspectionError('Phase 1 requires exactly one PyPI source distribution')
        dist = distributions[0]
        algorithm, expected = 'sha256', dist['digests']['sha256']
        urls = meta['info'].get('project_urls') or {}
        repos = {repository(v) for v in urls.values()} - {None}
        repo = next(iter(repos)) if len(repos) == 1 else None
        directory, git_head = '', None
        published = {'publication_time': dist.get('upload_time_iso_8601'), 'yanked': dist.get('yanked'),
                     'registry': 'https://pypi.org'}
        url = dist['url']
    blob = fetcher.get(url)
    actual = hashlib.new(algorithm, blob).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise InspectionError('Artifact digest does not match official registry metadata')
    if ecosystem == 'npm':
        published.update(npm_publication(fetcher, name, version))
    return {'ecosystem': ecosystem, 'name': name, 'version': version, 'publication': published,
            'artifact': {'url': url, 'digest': algorithm + ':' + actual, 'verified': True},
            'repository': 'https://github.com/' + repo if repo else None,
            'repo_slug': repo, 'directory': directory, 'git_head': git_head}, blob
