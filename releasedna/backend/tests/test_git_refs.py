import unittest
from unittest.mock import patch

import httpx

from app.core.safety import File, InspectionError, validate_url
from app.source_resolver.git_refs import advertised_tags
from app.source_resolver.resolve import resolve

SHA = 'a' * 40
OTHER = 'b' * 40


def advertisement(*refs):
    def pkt(line):
        data = line.encode()
        return f'{len(data) + 4:04x}'.encode() + data
    return pkt('# service=git-upload-pack\n') + b'0000' + b''.join(pkt(x + '\n') for x in refs) + b'0000'


class Source:
    def __init__(self, data, status=403):
        self.data, self.status, self.calls = data, status, []

    def json(self, url):
        response = httpx.Response(self.status, headers={'x-ratelimit-remaining': '0' if self.status == 403 else '10'}, request=httpx.Request('GET', url))
        response.raise_for_status()

    def get(self, url, limit=None):
        self.calls.append((url, limit))
        return self.data if '/info/refs?' in url else b'archive'


class GitRefsTests(unittest.TestCase):
    def test_lightweight_and_annotated_tags(self):
        fetcher = Source(advertisement(SHA + ' HEAD\0capability', OTHER + ' refs/tags/v1.0.0', SHA + ' refs/tags/v1.0.0^{}', SHA + ' refs/tags/1.0.0'))
        self.assertEqual(advertised_tags(fetcher, 'owner/repo', ['v1.0.0', '1.0.0', 'missing']), {'v1.0.0': SHA, '1.0.0': SHA})
        self.assertEqual(fetcher.calls[0][1], 8 * 1024 * 1024)

    def test_rejects_truncated_invalid_and_duplicate_advertisements(self):
        for data in (b'', b'ffffshort', b'0001', b'xxxx', advertisement(SHA + ' refs/tags/v1')[:-4], advertisement(SHA + ' refs/tags/v1', OTHER + ' refs/tags/v1'), advertisement('invalid refs/tags/v1')):
            with self.subTest(data=data), self.assertRaises(InspectionError):
                advertised_tags(Source(data), 'owner/repo', ['v1'])

    def release(self, **extra):
        return dict(repo_slug='owner/repo', ecosystem='npm', name='demo', version='1.0.0', **extra)

    def test_rate_limit_fallback_preserves_corroboration_and_exact_commit(self):
        fetcher = Source(advertisement(SHA + ' refs/tags/v1.0.0'))
        with patch('app.source_resolver.resolve.inspect_archive', return_value={'package.json': File(b'{"name":"demo","version":"1.0.0"}')}):
            evidence, _ = resolve(fetcher, self.release(git_head=SHA))
        self.assertTrue(evidence['identity_corroborated'])
        self.assertFalse(evidence['build_provenance_verified'])
        self.assertEqual(evidence['resolution_transport'], 'git_https_refs')
        self.assertEqual(fetcher.calls[-1][0], 'https://codeload.github.com/owner/repo/tar.gz/' + SHA)

    def test_disagreeing_tags_do_not_get_trusted(self):
        evidence, files = resolve(Source(advertisement(SHA + ' refs/tags/v1.0.0', OTHER + ' refs/tags/1.0.0')), self.release())
        self.assertEqual(evidence['tag_status'], 'conflicting')
        self.assertFalse(files)
        self.assertFalse(evidence['identity_corroborated'])

    def test_git_head_mismatch_and_missing_manifest_remain_candidates(self):
        for manifest, head in [(b'{"name":"demo","version":"1.0.0"}', OTHER), (b'{}', SHA)]:
            with patch('app.source_resolver.resolve.inspect_archive', return_value={'package.json': File(manifest)}):
                evidence, _ = resolve(Source(advertisement(SHA + ' refs/tags/v1.0.0')), self.release(git_head=head))
            self.assertFalse(evidence['identity_corroborated'])

    def test_other_http_errors_do_not_trigger_fallback(self):
        fetcher = Source(b'', status=500)
        with self.assertRaises(httpx.HTTPStatusError):
            resolve(fetcher, self.release())
        self.assertFalse(fetcher.calls)

    def test_github_allowlist_is_ref_discovery_only(self):
        validate_url('https://github.com/owner/repo.git/info/refs?service=git-upload-pack')
        for url in ('https://github.com/owner/repo', 'https://github.com/owner/repo.git/info/refs?service=git-receive-pack', 'https://github.com/owner/repo.git/info/refs?service=git-upload-pack&extra=1', 'https://127.0.0.1/owner/repo.git/info/refs?service=git-upload-pack'):
            with self.assertRaises(InspectionError):
                validate_url(url)


if __name__ == '__main__':
    unittest.main()
