import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock
from fastapi.testclient import TestClient
from app.api.main import create_app
from app.core.safety import File
from app.connectors.registry import npm_publication
from app.diff_engine.compare import compare, CLEAN_MEANING
from app.services.jobs import JobStore, Worker, QueueFull

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures/is-number-7.0.0.json'
REQUEST = {'ecosystem': 'npm', 'name': 'is-number', 'version': '7.0.0'}


def files(which):
    fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
    return {path: File(value['text'].encode(), value['executable']) for path, value in fixture[which].items()}


class ClassificationRegression(unittest.TestCase):
    def setUp(self):
        self.artifact, self.source = files('artifact_files'), files('source_files')

    def test_real_structure_counts_and_expected_omissions(self):
        report = compare(self.artifact, self.source, True)
        self.assertEqual(report['metrics'], {'artifact_file_count': 4, 'source_file_count': 15,
            'unique_comparison_paths': 15, 'identical_files': 4, 'added_files': 0, 'removed_files': 11, 'changed_files': 0})
        self.assertEqual(report['total_files_inspected'], 19)
        self.assertEqual(len(report['files']), 15)
        self.assertEqual(report['status'], 'CLEAN')
        omissions = [r for r in report['files'] if r['state'] == 'removed']
        self.assertTrue(all(r['classification'] == 'expected' for r in omissions))
        self.assertTrue({'development', 'tests', 'documentation'} <= {r['omission_kind'] for r in omissions})
        self.assertEqual(report['clean_definition'], CLEAN_MEANING)

    def test_missing_entrypoint_overrides_ignore_and_files(self):
        del self.artifact['index.js']
        self.source['.npmignore'] = File(b'index.js\n')
        report = compare(self.artifact, self.source, True)
        self.assertEqual(report['status'], 'REVIEW')
        self.assertIn('MISSING_ENTRYPOINT', report['risk_reasons'])
        finding = next(f for f in report['findings'] if f['rule'] == 'MISSING_ENTRYPOINT')
        self.assertEqual(finding['source_path'], 'index.js')
        self.assertIsNone(finding['artifact_path'])

    def test_runtime_reference_overrides_test_name_and_ignore(self):
        content = File(b"require('./tests/helper')")
        self.artifact['index.js'] = self.source['index.js'] = content
        self.source['tests/helper.js'] = File(b'module.exports=1')
        self.source['.npmignore'] = File(b'tests/\n')
        report = compare(self.artifact, self.source, True)
        row = next(r for r in report['files'] if r['path'] == 'tests/helper.js')
        self.assertEqual(row['omission_kind'], 'runtime')
        self.assertEqual(row['classification'], 'suspicious')

    def test_undeclared_runtime_file_without_packaging_rules(self):
        source = {'package.json': File(b'{"main":"index.js"}'), 'index.js': File(b'1'), 'lib/runtime.js': File(b'2')}
        report = compare({p:f for p,f in source.items() if p != 'lib/runtime.js'}, source, True)
        self.assertEqual(report['status'], 'REVIEW')
        self.assertIn('MISSING_RUNTIME_FILE', report['risk_reasons'])

    def test_unknown_omission_is_inconclusive(self):
        report = compare({'a': File(b'a')}, {'a': File(b'a'), 'unknown.dat': File(b'?')}, True)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['files'][1]['omission_kind'], 'unexplained')

    def test_literal_files_rule_explains_build_input(self):
        source = {'package.json': File(b'{"files":["dist"],"main":"dist/index.js"}'),
                  'dist/index.js': File(b'1'), 'src/index.ts': File(b'1')}
        report = compare({p:f for p,f in source.items() if p != 'src/index.ts'}, source, True)
        self.assertEqual(report['status'], 'CLEAN')
        self.assertEqual(report['files'][-1]['omission_rule'], 'NPM_FILES_EXCLUSION')

    def test_complex_ignore_not_treated_as_proof(self):
        source = {'index.js': File(b'1'), '.npmignore': File(b'lib/\n!lib/runtime.js'), 'lib/runtime.js': File(b'2')}
        report = compare({'index.js': source['index.js']}, source, True)
        self.assertIn('MISSING_RUNTIME_FILE', report['risk_reasons'])

    def test_exports_and_bin_missing(self):
        meta = File(b'{"exports":{".":"./dist/main.js"},"bin":{"x":"cli.js"}}')
        source = {'package.json': meta, 'dist/main.js': File(b'1'), 'cli.js': File(b'2')}
        report = compare({'package.json': meta}, source, True)
        self.assertEqual(sum(f['rule'] == 'MISSING_ENTRYPOINT' for f in report['findings']), 2)

    def test_source_confidence_independent_of_integrity(self):
        fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
        self.assertTrue(fixture['release']['artifact']['verified'])
        self.assertEqual(fixture['source_info']['confidence'], 'corroborated')
        self.assertFalse(fixture['source_info']['build_provenance_verified'])
        self.assertEqual(compare(self.artifact, self.source, False)['status'], 'INCONCLUSIVE')


class PublicationTests(unittest.TestCase):
    def test_time_from_exact_version(self):
        f = Mock()
        f.json.return_value = {'name':'is-number','time':{'7.0.0':'2018-07-04T15:08:58.238Z','modified':'2020-01-01T00:00:00Z'}}
        self.assertEqual(npm_publication(f,'is-number','7.0.0')['publication_time'], '2018-07-04T15:08:58.238Z')

    def test_missing_metadata_not_invented(self):
        f = Mock()
        for value in [{'name':'is-number'}, {'name':'is-number','time':{'modified':'2020-01-01T00:00:00Z'}},
                      {'name':'other','time':{'7.0.0':'2018-07-04T15:08:58.238Z'}},
                      {'name':'is-number','time':{'7.0.0':'invalid'}}]:
            f.json.return_value = value
            result = npm_publication(f,'is-number','7.0.0')
            self.assertIsNone(result['publication_time'])
            self.assertTrue(result['publication_time_limitation'])


class JobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'test.sqlite3'

    def wait_for(self, client, identity, state):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            job = client.get('/api/scans/' + identity).json()
            if job['state'] == state:
                return job
            time.sleep(.02)
        self.fail(f'Job never became {state}: {job}')

    def test_post_is_queued_and_worker_runs_asynchronously(self):
        gate, entered = threading.Event(), threading.Event()
        def scanner(**request):
            entered.set()
            gate.wait(5)
            return {'status':'CLEAN', 'error':None}
        with TestClient(create_app(self.path, scanner)) as client:
            try:
                response = client.post('/api/scans', json=REQUEST)
                self.assertEqual(response.status_code, 202)
                identity = response.json()['id']
                self.assertIn(response.json()['state'], ['queued','running'])
                self.assertTrue(entered.wait(2))
                self.assertEqual(client.get('/api/scans/'+identity).json()['state'], 'running')
                self.assertEqual(client.get('/health').status_code, 200)
                queued = client.post('/api/scans', json=REQUEST).json()
                self.assertEqual(queued['state'], 'queued')
            finally:
                gate.set()
            completed = self.wait_for(client, identity, 'completed')
            self.assertEqual(completed['result']['scan_id'], identity)

    def test_results_survive_new_app_lifespan(self):
        report = compare(files('artifact_files'), files('source_files'), True)
        with TestClient(create_app(self.path, lambda **kw: dict(report))) as client:
            identity = client.post('/api/scans', json=REQUEST).json()['id']
            before = self.wait_for(client, identity, 'completed')
        with TestClient(create_app(self.path, lambda **kw: self.fail('Completed job reran'))) as restarted:
            self.assertEqual(restarted.get('/api/scans/'+identity).json(), before)
            self.assertEqual(restarted.get('/api/scans').json()['items'][0]['id'], identity)

    def test_restart_fails_interrupted_and_resumes_queued(self):
        store = JobStore(self.path)
        interrupted = store.create(REQUEST)['id']
        store.claim()
        queued = store.create(REQUEST)['id']
        with TestClient(create_app(self.path, lambda **kw: {'status':'CLEAN'})) as client:
            recovered = client.get('/api/scans/'+interrupted).json()
            self.assertEqual(recovered['state'], 'failed')
            self.assertIn('Interrupted', recovered['error'])
            self.wait_for(client, queued, 'completed')

    def test_exception_and_engine_error_fail_job(self):
        for scanner in [Mock(side_effect=RuntimeError('worker error')), lambda **kw: {'status':'INCONCLUSIVE', 'error':'download failed'}]:
            with TestClient(create_app(self.path, scanner)) as client:
                identity = client.post('/api/scans', json=REQUEST).json()['id']
                self.assertTrue(self.wait_for(client, identity, 'failed')['error'])

    def test_api_validation_history_and_frontend(self):
        with TestClient(create_app(self.path, lambda **kw: {'status':'CLEAN'})) as client:
            self.assertEqual(client.post('/api/scans', json={**REQUEST, 'name':'../bad'}).status_code, 422)
            self.assertEqual(client.get('/api/scans/missing').status_code, 404)
            self.assertEqual(client.get('/api/scans?limit=101').status_code, 422)
            self.assertEqual(client.get('/api/scans').json()['total'], 0)
            self.assertIn('scan-form', client.get('/').text)
            self.assertEqual(client.get('/assets/app.js').status_code, 200)

    def test_queue_bound(self):
        store = JobStore(self.path)
        for _ in range(20):
            store.create(REQUEST)
        with self.assertRaises(QueueFull):
            store.create(REQUEST)

    def test_second_worker_rejected(self):
        first = Worker(JobStore(self.path), lambda **kw: {})
        second = Worker(JobStore(self.path), lambda **kw: {})
        first.start()
        try:
            with self.assertRaises(RuntimeError):
                second.start()
        finally:
            first.close()
