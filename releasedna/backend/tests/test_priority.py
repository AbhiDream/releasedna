import copy
import gzip
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from app.core.safety import File
from app.diff_engine.compare import compare
from app.diff_engine.fingerprint import detector_fingerprint,FILES
from app.adversarial_corpus import run
from app.services.jobs import JobStore
from app.services.monitor import ReleaseMonitor,registry_poll
from app.services.explanation import explain,ExplanationUnavailable,fingerprint
from app.api.main import create_app
from fastapi.testclient import TestClient


class DetectorPriorityTests(unittest.TestCase):
    def test_detector_fingerprint_is_portable_but_content_sensitive(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in FILES: (Path(folder)/name).write_bytes(b'first\nsecond\n')
            expected=detector_fingerprint(folder)
            for name in FILES: (Path(folder)/name).write_bytes(b'first\r\nsecond\r\n')
            self.assertEqual(expected,detector_fingerprint(folder))
            (Path(folder)/FILES[0]).write_bytes(b'changed\r\n')
            self.assertNotEqual(expected,detector_fingerprint(folder))

    def test_noncode_changed_and_added_scored(self):
        for path in ('build.m4','a.blob','a.sh'):
            for source in ({},{path:File(b'old')}):
                r=compare({path:File(b'new')},source,True)
                self.assertGreater(r['risk_score'],0)
                self.assertTrue(r['findings'][0]['artifact_path']==path)

    def test_binary_script_and_entropy(self):
        r=compare({'blob':File(b'\x00m4_syscmd([echo fixture])')},{},True)
        f=next(f for f in r['findings'] if f['rule']=='SHELL_PIPELINE')
        self.assertEqual(f['evidence'][0]['byte_offset'],1)
        blob=bytes(range(256))*8
        self.assertIn('HIGH_ENTROPY_CHANGE',compare({'blob':File(blob)},{},True)['risk_reasons'])
        self.assertEqual(compare({'blob':File(blob)},{'blob':File(blob)},True)['findings'],[])

    def test_entropy_skips_known_compressed_assets(self):
        compressed=gzip.compress(bytes(range(256))*1024,mtime=0)
        for path,data in (('asset.gz',bytes(range(256))*8),('asset.bin',compressed),
                          ('module.wasm',b'\x00asm'+bytes(range(256))*8),
                          ('font.woff2',b'wOF2'+bytes(range(256))*8),
                          ('font.otf',b'OTTO'+bytes(range(256))*8)):
            with self.subTest(path=path):
                report=compare({path:File(data)},{},True)
                self.assertNotIn('HIGH_ENTROPY_CHANGE',report['risk_reasons'])
                row=next(x for x in report['files'] if x['path']==path)
                self.assertIn('entropy_rule_skipped',row)
                self.assertEqual(row['classification'],'generated_unverified')

    def test_regex_exec_not_dynamic_execution(self):
        baseline={'index.js':File(b'module.exports = 1;\n')}
        artifact={'index.js':File(b'module.exports = 1;\nconst match = /pattern/.exec("input");\n')}
        report=compare(artifact,baseline,True)
        self.assertNotIn('DYNAMIC_EXECUTION',report['risk_reasons'])
        self.assertNotIn('UNEXPLAINED_CODE',report['risk_reasons'])
        self.assertEqual(report['findings'],[])
        self.assertEqual(next(x for x in report['files'] if x['path']=='index.js')['classification'],'expected')
        self.assertIn('DYNAMIC_EXECUTION',compare({'a.py':File(b'exec("pass")')},{},True)['risk_reasons'])

    def test_specific_obfuscation_patterns_have_precise_findings(self):
        cases = {
            'string-built-eval': (b"eval('con' + 'sole.log(1)')", 'OBFUSCATED_DYNAMIC_EXECUTION'),
            'bracket-concat-eval': (b"x['ev'+'al']('1')", 'OBFUSCATED_DYNAMIC_EXECUTION'),
            'string-built-function': (b"Function('ret'+'urn 1')", 'OBFUSCATED_DYNAMIC_EXECUTION'),
            'bracket-concat-function': (b"obj['Fun'+'ction']('return 1')", 'OBFUSCATED_DYNAMIC_EXECUTION'),
            'computed-this-call': (b"this[var]('value')", 'OBFUSCATED_DYNAMIC_EXECUTION'),
            'hex-escaped-require': (b"require('\\x63\\x68ild_process')", 'OBFUSCATED_MODULE_LOAD'),
            'bracket-concat-require': (b"pkg['req'+'uire']('child_process')", 'OBFUSCATED_MODULE_LOAD'),
            'browser-fetch-hook': (b'window.fetch = function(input) { return original(input); };', 'BROWSER_API_HOOK'),
            'hex-obfuscator-array': (b'var _0x4f2a = ["alpha", "beta"];', 'OBFUSCATOR_IDENTIFIER'),
            'short-obfuscator-array': (b'const _0x1 = ["alpha", "beta"];', 'OBFUSCATOR_IDENTIFIER'),
        }
        for label, (payload, rule) in cases.items():
            with self.subTest(case=label):
                report=compare({'dist/index.js':File(payload)},{},True)
                finding=next((item for item in report['findings'] if item['rule']==rule),None)
                self.assertIsNotNone(finding,report['risk_reasons'])
                self.assertEqual(finding['artifact_path'],'dist/index.js')
                self.assertIn('static heuristic',finding['message'])
                self.assertNotIn('UNEXPLAINED_CODE',report['risk_reasons'])

    def test_escape_density_is_parser_scoped_and_per_kb(self):
        escapes=b'\\x61'*8
        cases=(
            ('dense-string',b'const s="'+b'\\x61'*16+b'";','ESCAPE_DENSITY'),
            ('dense-template',b'const s=`'+b'\\u0061'*16+b'`;','ESCAPE_DENSITY'),
            ('comments',b'// '+b'\\x61'*20+b'\nconst s="plain";','NO_ESCAPE_DENSITY'),
            ('regex-literal',b'const r=/'+b'\\x61'*20+b'/;','NO_ESCAPE_DENSITY'),
            ('declaration-file',b'declare const s: "'+b'\\x61'*20+b'";','NO_ESCAPE_DENSITY'),
            ('below-per-kb',b'/*'+b'a'*1018+b'*/ const s="'+b'\\x61'*8+b'\\x62'*4+b'";','NO_ESCAPE_DENSITY'),
        )
        for label,payload,expected in cases:
            with self.subTest(case=label):
                report=compare({'dist/index.d.ts' if label=='declaration-file' else 'dist/index.js':File(payload)},{},True)
                if expected=='ESCAPE_DENSITY': self.assertIn('ESCAPE_DENSITY',report['risk_reasons'])
                else: self.assertNotIn('ESCAPE_DENSITY',report['risk_reasons'])

    def test_obfuscator_rule_does_not_flag_plain_hex_or_local_binding(self):
        for text in (b'const _0x = 1;', b'const _0xabc = ordinaryData;', b"require('child_process');", b'const path="C:\\x";'):
            with self.subTest(text=text):
                rules={item['rule'] for item in compare({'dist/index.js':File(text)},{},True)['findings']}
                if text == b"require('child_process');":
                    self.assertNotIn('OBFUSCATED_MODULE_LOAD',rules)
                else:
                    self.assertNotIn('OBFUSCATOR_IDENTIFIER',rules)
                self.assertNotIn('ESCAPE_DENSITY',rules)

    def test_development_and_sandbox_omissions_need_a_runtime_reference(self):
        for path in ('karma.conf.cjs','sandbox/fixture.js','sandbox/data.json','config/dev.json','configs/build.json'):
            with self.subTest(path=path):
                source={path:File(b'fixture')}
                row=next(item for item in compare({},source,True)['files'] if item['path']==path)
                self.assertEqual(row['classification'],'expected')
                self.assertNotEqual(row['omission_rule'],'MISSING_RUNTIME_FILE')
        source={'package.json':File(b'{"main":"karma.conf.cjs"}'),'karma.conf.cjs':File(b'module.exports={}')}
        row=next(item for item in compare({},source,True)['files'] if item['path']=='karma.conf.cjs')
        self.assertEqual(row['omission_rule'],'MISSING_ENTRYPOINT')
        self.assertEqual(row['classification'],'suspicious')

    def test_dev_omissions_preserve_entrypoints_and_imports(self):
        for path in ('.eslintrc.cjs','eslint.config.js','bin/dev.js','tasks/check.py'):
            source={path:File(b'void 0;')}
            self.assertNotIn('MISSING_RUNTIME_FILE',compare({},source,True)['risk_reasons'])
        source={'bin/cli.js':File(b'void 0;'),'package.json':File(b'{"bin":"bin/cli.js"}')}
        self.assertIn('MISSING_ENTRYPOINT',compare({'package.json':source['package.json']},source,True)['risk_reasons'])
        source={'bin/dev.js':File(b'void 0;')}
        self.assertIn('MISSING_RUNTIME_FILE',compare({'index.js':File(b"require('./bin/dev.js')")},source,True)['risk_reasons'])
        source={'tasks/check.py':File(b'pass')}
        self.assertIn('MISSING_RUNTIME_FILE',compare({'app.py':File(b'from tasks import check')},source,True)['risk_reasons'])
        meta=File(b'{"scripts":{"install":"node ./bin/setup.js"}}')
        source={'package.json':meta,'bin/setup.js':File(b'void 0;')}
        self.assertIn('MISSING_ENTRYPOINT',compare({'package.json':meta},source,True)['risk_reasons'])

    def test_declaration_pair_and_rooted_files(self):
        meta=File(b'{"files":["/dist"],"scripts":{"build":"tsc"}}')
        r=compare({'package.json':meta,'dist/a.d.ts':File(b'export declare const a: number;')},{'package.json':meta,'src/a.ts':File(b'export const a = 1;')},True)
        row=next(r for r in r['files'] if r['path']=='dist/a.d.ts')
        self.assertEqual(row['build_evidence']['declaration_sources'],['src/a.ts'])
        self.assertFalse(row['build_evidence']['equivalence_verified'])

    def test_corpus_metrics_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            a=run(Path(directory)/'a.json'); b=run(Path(directory)/'b.json')
            self.assertEqual(a,b)
            allrow=a['table'][-1]
            self.assertEqual(allrow['TP']+allrow['FN'],11)
            self.assertEqual(allrow['FP']+allrow['TN'],4)
            self.assertEqual((allrow['FP'],allrow['TN']),(0,4))

    def test_cache_explanation_never_exempts_payloads(self):
        p='tests/.pytest_cache/v/cache/nodeids'
        self.assertEqual(compare({p:File(b'["test_a.py::test_ok"]')},{},True)['findings'],[])
        self.assertIn('UNEXPLAINED_NONCODE',compare({p:File(b'["opaque blob"]')},{},True)['risk_reasons'])
        self.assertIn('DYNAMIC_EXECUTION',compare({p:File(b'["test_a.py::eval(1)"]')},{},True)['risk_reasons'])
        path='tests/.pytest_cache/payload.m4'
        self.assertIn('SHELL_PIPELINE',compare({path:File(b'm4_syscmd([echo fixture])')},{},True)['risk_reasons'])

    def test_esm_metadata_only_for_declared_import_outputs(self):
        meta=File(b'{"exports":{".":{"import":"./dist/esm/index.js"}},"scripts":{"build":"tsc"}}')
        source={'package.json':meta}
        path='dist/esm/package.json'
        self.assertEqual(compare({**source,path:File(b'{"type":"module"}')},source,True)['findings'],[])
        self.assertIn('UNEXPLAINED_NONCODE',compare({**source,path:File(b'{"type":"module","scripts":{"test":"anything"}}')},source,True)['risk_reasons'])


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=JobStore(Path(self.temp.name)/'db')
        self.worker=type('WorkerStub',(),{'wake':threading.Event()})()
        self.response=(200,'v1',['1.0.0'])
        self.calls=[]
        def poll(ecosystem,name,etag):
            self.calls.append(etag)
            return self.response
        self.monitor=ReleaseMonitor(self.store,self.worker,poll)
        self.identity=self.monitor.add('npm','fixture')

    def tearDown(self): self.temp.cleanup()

    def test_etag_dedup_restart_and_local_alerts(self):
        self.monitor.tick(True)
        self.assertEqual(self.store.history()['total'],0)
        self.response=(304,'v1',[]);self.monitor.tick(True)
        self.assertEqual(self.calls[-1],'v1')
        self.response=(200,'v2',['1.0.0','1.0.1']);self.monitor.tick(True)
        self.monitor.tick(True)
        self.assertEqual(self.store.history()['total'],1)
        job=self.store.claim();self.store.finish(job['id'],{'status':'REVIEW','findings':[{}]})
        restarted=ReleaseMonitor(JobStore(self.store.path),self.worker,lambda *args:self.response)
        restarted.tick(True);restarted.tick(True)
        self.assertEqual(self.store.history()['total'],1)
        self.assertEqual(len(restarted.snapshot()['alerts']),2)

    def test_queue_full_does_not_lose_release(self):
        self.monitor.tick(True)
        for i in range(20):self.store.create({'ecosystem':'npm','name':'other','version':str(i)})
        self.response=(200,'v2',['1.0.0','1.0.1']);self.monitor.tick(True)
        self.assertIsNone(self.monitor.snapshot()['watches'][0]['etag'])
        job=self.store.claim();self.store.finish(job['id'],{})
        self.monitor.tick(True)
        self.assertEqual(self.store.history()['total'],21)

    def test_error_retains_etag_and_watch_dedup(self):
        self.monitor.tick(True)
        self.assertEqual(self.monitor.add('npm','fixture'),self.identity)
        def fail(*args): raise ValueError('fixture network failure')
        self.monitor.poller=fail; self.monitor.tick(True)
        row=self.monitor.snapshot()['watches'][0]
        self.assertEqual(row['etag'],'v1');self.assertIn('failure',row['error'])
        self.monitor.remove(self.identity)
        self.assertEqual(self.monitor.snapshot()['watches'],[])


class ExplanationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=JobStore(Path(self.temp.name)/'db')
        self.job=self.store.create({'ecosystem':'npm','name':'fixture','version':'1'})
        self.store.claim()
        self.store.finish(self.job['id'],compare({'a.m4':File(b'm4_syscmd([echo fixture])')},{},True))

    def tearDown(self): self.temp.cleanup()

    def test_model_cannot_mutate_frozen_result_and_is_cached(self):
        before=self.store.get(self.job['id'])['result']; calls=[]
        def model(payload):
            calls.append(payload)
            self.assertIn('plain English only',payload['messages'][0]['content'])
            self.assertIn('Do not use Hindi or Hinglish',payload['messages'][0]['content'])
            return json.dumps({'explanations':[{'finding_id':f['id'],'text':'Static indicator, review needed.'} for f in before['findings']]})
        result=explain(self.store,self.job['id'],model)
        self.assertEqual(result['report_sha256'],fingerprint(before))
        self.assertEqual(explain(self.store,self.job['id'],model),result)
        self.assertEqual(len(calls),1)
        self.assertEqual(self.store.get(self.job['id'])['result'],before)

    def test_score_and_unknown_id_outputs_rejected(self):
        for output in ({'score':0,'explanations':[]},{'explanations':[{'finding_id':'fake','text':'safe'}]}, {'explanations':[]}):
            with self.assertRaises(ExplanationUnavailable): explain(self.store,self.job['id'],lambda p:json.dumps(output))

    def test_missing_key_is_explicit_no_network(self):
        with patch.dict('os.environ',{},clear=True), patch('httpx.Client') as client:
            with self.assertRaisesRegex(ExplanationUnavailable,'not configured'):explain(self.store,self.job['id'])
            client.assert_not_called()


class PriorityAPITests(unittest.TestCase):
    def test_watch_and_explanation_endpoints(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ',{},clear=True):
            app=create_app(Path(directory)/'db',lambda **kw:compare({'a.m4':File(b'm4_syscmd([echo fixture])')},{},True),lambda *args:(200,'test',['1.0.0']))
            with TestClient(app) as client:
                watch=client.post('/api/monitor',json={'ecosystem':'npm','name':'fixture'})
                self.assertEqual(watch.status_code,201)
                self.assertEqual(len(client.get('/api/monitor').json()['watches']),1)
                job=client.post('/api/scans',json={'ecosystem':'npm','name':'fixture','version':'1.0.0'}).json()
                for _ in range(100):
                    saved=client.get('/api/scans/'+job['id']).json()
                    if saved['state']=='completed':break
                    time.sleep(.01)
                self.assertEqual(saved['state'],'completed')
                response=client.post('/api/scans/'+job['id']+'/explanation')
                self.assertEqual(response.status_code,503)
                self.assertIn('not configured',response.json()['detail'])
                self.assertFalse(client.get('/api/explanation/config').json()['configured'])
                self.assertEqual(client.get('/api/scans/'+job['id']).json()['result'],saved['result'])
                self.assertEqual(client.delete('/api/monitor/'+watch.json()['id']).status_code,204)
