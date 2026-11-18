import unittest
from unittest.mock import patch
import httpx
from app.core.safety import Fetcher, InspectionError, File
from app.source_resolver.resolve import resolve
from app.services.scan import scan

SHA = 'a' * 40


class FakeSource:
    def json(self, url):
        if '/git/ref/tags/v1.0.0' in url:
            return {'object': {'type': 'commit', 'sha': SHA}}
        request = httpx.Request('GET', url)
        response = httpx.Response(404, request=request)
        raise httpx.HTTPStatusError('Missing tag', request=request, response=response)

    def get(self, url):
        return b'archive placeholder; inspector mocked separately'


class ResolutionTests(unittest.TestCase):
    def release(self, **kwargs):
        return {'repo_slug': 'owner/repo', 'version': '1.0.0', 'name': 'demo', 'ecosystem': 'npm', **kwargs}

    def test_source_identity_correlated(self):
        with patch('app.source_resolver.resolve.inspect_archive', return_value={'package.json': File(b'{"name":"demo","version":"1.0.0"}')}):
            evidence, _ = resolve(FakeSource(), self.release(git_head=SHA))
        self.assertTrue(evidence['identity_corroborated'])

    def test_tag_head_disagreement(self):
        with patch('app.source_resolver.resolve.inspect_archive', return_value={'package.json': File(b'{"name":"demo","version":"1.0.0"}')}):
            evidence, _ = resolve(FakeSource(), self.release(git_head='b' * 40))
        self.assertFalse(evidence['identity_corroborated'])
        self.assertIn('npm gitHead disagrees with release tag', evidence['reasons'])

    def test_manifest_disagreement(self):
        with patch('app.source_resolver.resolve.inspect_archive', return_value={'package.json': File(b'{"name":"other","version":"1.0.0"}')}):
            evidence, _ = resolve(FakeSource(), self.release())
        self.assertFalse(evidence['identity_corroborated'])

    def test_missing_repo(self):
        evidence, files = resolve(FakeSource(), self.release(repo_slug=None))
        self.assertFalse(evidence['identity_corroborated'])
        self.assertFalse(files)

    def test_network_failure_is_inconclusive(self):
        with patch('app.services.scan.fetch_release', side_effect=httpx.ConnectError('offline')):
            report = scan('npm', 'demo', '1.0.0')
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertIsNone(report['risk_score'])
        self.assertIn('offline', report['limitations'][0])

    def test_redirect_validation(self):
        visited = []
        def handler(request):
            visited.append(str(request.url))
            return httpx.Response(302, headers={'location': 'https://127.0.0.1/private'})
        fetcher = Fetcher()
        fetcher.client.close()
        fetcher.client = httpx.Client(transport=httpx.MockTransport(handler))
        try:
            with self.assertRaises(InspectionError):
                fetcher.get('https://registry.npmjs.org/demo')
            self.assertEqual(len(visited), 1)
        finally:
            fetcher.close()

    def test_download_limit(self):
        fetcher = Fetcher()
        fetcher.client.close()
        fetcher.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'12345')))
        try:
            with self.assertRaises(InspectionError):
                fetcher.get('https://registry.npmjs.org/demo', limit=4)
        finally:
            fetcher.close()
