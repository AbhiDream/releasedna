import hashlib
import io
import json
import tarfile
import unittest
import zipfile
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.api.main import app, slot
from app.core.safety import File, InspectionError, inspect_archive, validate_url
from app.connectors.registry import fetch_release, validate_input
from app.diff_engine.compare import compare


def archive(files, link=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
        for path, data in files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(data)
            if link:
                entry.type, entry.linkname = tarfile.SYMTYPE, '/etc/passwd'
            tf.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


class SafetyTests(unittest.TestCase):
    def test_normal_archive(self):
        self.assertEqual(inspect_archive(archive({'package/index.js': b'ok'}))['index.js'].data, b'ok')

    def test_traversal(self):
        for path in ['package/../../escape', '/absolute', 'package/C:evil', 'package/a\\b']:
            with self.subTest(path=path), self.assertRaises(InspectionError):
                inspect_archive(archive({path: b'x'}))

    def test_links(self):
        with self.assertRaises(InspectionError):
            inspect_archive(archive({'package/link': b''}, link=True))

    def test_case_collision(self):
        with self.assertRaises(InspectionError):
            inspect_archive(archive({'package/A': b'a', 'package/a': b'b'}))

    def test_member_limit(self):
        with patch('app.core.safety.MAX_FILE', 10), self.assertRaises(InspectionError):
            inspect_archive(archive({'package/a': b'a' * 11}))

    def test_zip_link(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as z:
            info = zipfile.ZipInfo('package/link')
            info.external_attr = 0o120777 << 16
            z.writestr(info, '/etc/passwd')
        with self.assertRaises(InspectionError):
            inspect_archive(output.getvalue())

    def test_unapproved_urls(self):
        for url in ['http://registry.npmjs.org/a', 'https://127.0.0.1/a', 'https://registry.npmjs.org.evil.test/a',
                    'https://user:pass@registry.npmjs.org/a', 'https://registry.npmjs.org:444/a']:
            with self.subTest(url=url), self.assertRaises(InspectionError):
                validate_url(url)

    def test_strict_input(self):
        for name in ['../x', 'https://evil.test', '@scope/../../x']:
            with self.assertRaises(InspectionError):
                validate_input('npm', name, '1.0.0')
        validate_input('npm', '@scope/pkg', '1.0.0-beta.1')

    def test_digest_mismatch(self):
        class Fake:
            def json(self, url):
                return {'name': 'demo', 'version': '1.0.0', 'dist': {'tarball': 'https://registry.npmjs.org/demo.tgz',
                        'integrity': 'sha256-' + 'AA' * 21 + 'A='}}
            def get(self, url):
                return b'modified'
        with self.assertRaises(InspectionError):
            fetch_release(Fake(), 'npm', 'demo', '1.0.0')


class EvidenceTests(unittest.TestCase):
    def test_identical_verified(self):
        files = {'index.js': File(b'module.exports = 1;')}
        self.assertEqual(compare(files, files, True)['status'], 'CLEAN')

    def test_identical_unverified(self):
        files = {'index.js': File(b'module.exports = 1;')}
        self.assertEqual(compare(files, files, False)['status'], 'INCONCLUSIVE')

    def test_tampering_same_archive_pipeline(self):
        source = {'package/package.json': b'{"name":"demo","version":"1.0.0"}', 'package/index.js': b'module.exports=1;'}
        tampered = dict(source)
        tampered['package/package.json'] = b'{"name":"demo","version":"1.0.0","scripts":{"postinstall":"node payload.js"}}'
        tampered['package/payload.js'] = b"require('child_process').execSync('echo synthetic-fixture');"
        result = compare(inspect_archive(archive(tampered)), inspect_archive(archive(source)), True)
        self.assertEqual(result['status'], 'HIGH_RISK')
        self.assertTrue({'INSTALL_SCRIPT_CHANGED', 'PROCESS_EXECUTION'} <= set(result['risk_reasons']))
        for finding in result['findings']:
            self.assertTrue(finding['artifact_path'])
            self.assertTrue(finding['rule'])

    def test_existing_capability_not_flagged(self):
        s = {'a.js': File(b"require('child_process');\n// old")}
        a = {'a.js': File(b"require('child_process');\n// updated")}
        self.assertNotIn('PROCESS_EXECUTION', compare(a, s, True)['risk_reasons'])

    def test_generated_directory_not_blindly_trusted(self):
        result = compare({'dist/bundle.js': File(b'eval(atob("abc"));')}, {'src/a.js': File(b'1')}, True)
        self.assertIn('DYNAMIC_EXECUTION', result['risk_reasons'])

    def test_metadata_expected(self):
        result = compare({'PKG-INFO': File(b'Name: demo')}, {'README.md': File(b'demo')}, True)
        self.assertEqual(result['expected_generated_differences'], ['PKG-INFO'])

    def test_unexplained_noncode_is_inconclusive(self):
        self.assertEqual(compare({'x.dat': File(b'unknown')}, {'a': File(b'a')}, True)['status'], 'INCONCLUSIVE')

    def test_sourcemap_mismatch(self):
        data = json.dumps({'sources': ['src/a.js'], 'sourcesContent': ['tampered']}).encode()
        result = compare({'out.js.map': File(data)}, {'src/a.js': File(b'original')}, True)
        self.assertIn('SOURCEMAP_SOURCE_MISMATCH', result['risk_reasons'])

    def test_matching_sourcemap_does_not_prove_bundle(self):
        data = json.dumps({'sources': ['a.js'], 'sourcesContent': ['original']}).encode()
        result = compare({'out.js.map': File(data)}, {'a.js': File(b'original')}, True)
        self.assertEqual(result['status'], 'INCONCLUSIVE')

    def test_new_executable(self):
        result = compare({'helper': File(b'hello', True)}, {'helper': File(b'hello')}, True)
        self.assertIn('EXECUTABLE_ADDED', result['risk_reasons'])


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        self.assertEqual(self.client.get('/health').status_code, 200)

    def test_input(self):
        self.assertEqual(self.client.post('/api/scans', json={'ecosystem': 'npm', 'name': '../bad', 'version': '1'}).status_code, 422)

    def test_concurrency(self):
        slot.acquire()
        try:
            self.assertEqual(self.client.post('/api/scans', json={'ecosystem': 'npm', 'name': 'demo', 'version': '1'}).status_code, 429)
        finally:
            slot.release()

    def test_pipeline_delegation(self):
        with patch('app.api.main.scan', return_value={'status': 'INCONCLUSIVE'}) as mock:
            response = self.client.post('/api/scans', json={'ecosystem': 'npm', 'name': 'demo', 'version': '1'})
            self.assertEqual(response.json()['status'], 'INCONCLUSIVE')
            mock.assert_called_once_with('npm', 'demo', '1')


if __name__ == '__main__':
    unittest.main()
