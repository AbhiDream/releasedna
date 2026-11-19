import json
import re
import tomllib
from urllib.parse import quote
import httpx
from app.core.safety import InspectionError, inspect_archive, safe_path


def resolve(fetcher, release):
    slug, version = release['repo_slug'], release['version']
    evidence = {'commit': None, 'tag': None, 'tag_status':'unknown', 'confidence': 'unresolved',
                'identity_corroborated': False, 'build_provenance_verified': False, 'reasons': []}
    if not slug:
        evidence['reasons'].append('No unambiguous supported GitHub repository in registry metadata')
        return evidence, {}
    commits = {}
    for tag in ('v' + version, version, release['name'].split('/')[-1] + '@' + version):
        try:
            ref = fetcher.json(f'https://api.github.com/repos/{slug}/git/ref/tags/{quote(tag, safe="")}')
            obj = ref['object']
            for _ in range(3):
                if obj['type'] != 'tag':
                    break
                obj = fetcher.json(f'https://api.github.com/repos/{slug}/git/tags/{obj["sha"]}')['object']
            if obj['type'] == 'commit' and re.fullmatch(r'[0-9a-f]{40}', obj['sha']):
                commits[tag] = obj['sha']
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
    evidence['tag_status']='matched' if commits else 'missing'
    if len(set(commits.values())) > 1:
        evidence['tag_status']='conflicting'
        evidence['reasons'].append('Release tag candidates disagree on source commit')
        return evidence, {}
    head = release.get('git_head')
    if head and not re.fullmatch(r'[0-9a-f]{40}', head):
        head = None
    if commits:
        tag, sha = next(iter(commits.items()))
        evidence.update(tag=tag, commit=sha)
        if head and head != sha:
            evidence['reasons'].append('npm gitHead disagrees with release tag')
    elif head:
        commit = fetcher.json(f'https://api.github.com/repos/{slug}/commits/{head}')
        if commit['sha'] != head:
            raise InspectionError('Source commit identity mismatch')
        sha = head
        evidence.update(commit=sha)
        evidence['reasons'].append('No matching release tag; registry gitHead is only a candidate')
    else:
        evidence['reasons'].append('No matching release tag or usable registry gitHead')
        return evidence, {}
    url = f'https://codeload.github.com/{slug}/tar.gz/{sha}'
    blob = fetcher.get(url)
    import hashlib
    evidence.update(archive_url=url, archive_sha256=hashlib.sha256(blob).hexdigest())
    files = inspect_archive(blob)
    directory = release.get('directory')
    if directory:
        directory = safe_path(directory).rstrip('/') + '/'
        files = {p[len(directory):]: f for p, f in files.items() if p.startswith(directory)}
        if not files:
            raise InspectionError('Repository package directory is absent')
    identity = False
    try:
        if release['ecosystem'] == 'npm' and 'package.json' in files:
            manifest = json.loads(files['package.json'].data)
            identity = manifest.get('name') == release['name'] and manifest.get('version') == version
        elif 'pyproject.toml' in files:
            manifest = tomllib.loads(files['pyproject.toml'].data.decode())
            project = manifest.get('project', manifest.get('tool', {}).get('poetry', {}))
            norm = lambda s: re.sub(r'[-_.]+', '-', s).lower()
            identity = norm(project.get('name', '')) == norm(release['name']) and project.get('version') == version
    except (ValueError, UnicodeError):
        pass
    if not identity:
        evidence['reasons'].append('Source manifest does not statically corroborate package name and version')
    verified = bool(commits and identity and (not head or head == sha))
    evidence.update(identity_corroborated=verified, confidence='corroborated' if verified else 'candidate')
    evidence['reasons'].append('Tag/manifest matching is not a cryptographic build provenance verification')
    return evidence, files
