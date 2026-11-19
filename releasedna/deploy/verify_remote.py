"""Opt-in smoke checks against YOUR deployed workspace. Never prints its access key.

Usage: set RELEASEDNA_API_TOKEN in the shell; python verify_remote.py https://your-service.onrender.com
Creates two official scan jobs and one harmless text comparison. Export the report before a free service restarts.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--output', type=Path, default=Path('remote-verification.json'))
    args = parser.parse_args()
    base = args.url.rstrip('/')
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        parser.error('Use the HTTPS origin of your deployed workspace, without a path or credentials')
    key = os.environ.get('RELEASEDNA_API_TOKEN', '')
    if len(key) < 32:
        parser.error('Set RELEASEDNA_API_TOKEN in the environment; never pass it on the command line')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise RuntimeError('Redirect rejected to keep the access key on the selected origin')
    opener = urllib.request.build_opener(NoRedirect)
    def request(path, body=None, raw=False, auth=True):
        headers = {'Authorization': 'Bearer ' + key} if auth else {}
        if body is not None:
            headers['Content-Type'] = 'application/octet-stream' if raw else 'application/json'
            body = body if raw else json.dumps(body).encode()
        with opener.open(urllib.request.Request(base + path, data=body, headers=headers), timeout=60) as response:
            return json.load(response)
    health = request('/health', auth=False)
    assert health['auth_required'] and health['scan_concurrency'] == 1, health
    try:
        request('/api/scans', auth=False)
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    else:
        raise AssertionError('Remote history is not protected')
    batch = request('/api/scans/batch', {'packages': [
        {'ecosystem': 'npm', 'name': 'is-number', 'version': '7.0.0'},
        {'ecosystem': 'pypi', 'name': 'packaging', 'version': '25.0'}]})
    artifact = request('/api/uploads?label=harmless-build.txt', b'normal\nm4_syscmd([printf fixture])\n', True)['id']
    source = request('/api/uploads?label=source-build.txt', b'normal\n', True)['id']
    text = request('/api/text-comparisons', {'artifact_id': artifact, 'source_id': source, 'name': 'build.txt'})
    ids = [j['id'] for j in batch['items']] + [text['id']]
    end = time.monotonic() + 480
    timeline, jobs = [], []
    while time.monotonic() < end:
        jobs = [request('/api/scans/' + identity) for identity in ids]
        states = [j['state'] for j in jobs]
        timeline.append(states)
        assert states.count('running') <= 1, states
        if all(state in ('completed', 'failed') for state in states):
            break
        time.sleep(2)
    report = {'health': health, 'job_ids': ids, 'observed_states': timeline, 'jobs': jobs,
              'scope': 'Smoke checks only; container isolation and provider restart persistence require separate verification.'}
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    assert all(j['state'] == 'completed' for j in jobs), 'Not every job completed; inspect saved evidence'
    assert jobs[0]['result']['metrics']['identical_files'] == 4
    assert jobs[2]['result']['files'][0]['path'] == 'build.txt'
    assert 'SHELL_PIPELINE' in jobs[2]['result']['risk_reasons']
    print('PASS: authenticated remote API, batch completion, observed serial execution and exact text finding.')
    print('Evidence:', args.output)


if __name__ == '__main__':
    main()
