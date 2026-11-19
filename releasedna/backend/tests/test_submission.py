import io
import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.api.main import create_app
from app.core.safety import File, InspectionError
from app.diff_engine.compare import compare
from app.diff_engine.syntax import equivalent
from app.evaluation_fixtures import pack
from app.services.jobs import JobStore
from app.services.local_compare import compare_archives, archive_files
from app.services.process_boundary import bounded_inspection


def files(items): return {k:File(v,False) for k,v in items.items()}


class SubmissionTests(unittest.TestCase):
    def test_declared_development_cleanup_does_not_hide_runtime_changes(self):
        base={'name':'demo','main':'index.js','devDependencies':{'clean-publish':'1','prettier':'1'},'prettier':{'semi':False},'scripts':{'test':'test'}}
        def report(value,src=base): return compare(files({'package.json':json.dumps(value).encode()}),files({'package.json':json.dumps(src).encode()}),True)
        self.assertEqual(report({'name':'demo','main':'index.js'})['risk_score'],0)
        self.assertGreater(report({'name':'demo','main':'other.js'})['risk_score'],0)
        self.assertGreater(report({'name':'demo','main':'index.js'}, {**base,'scripts':{'postinstall':'echo fixture'}})['risk_score'],0)

    def test_registered_ecosystem_adapter_is_used(self):
        from app.connectors.adapters import register_adapter,ADAPTERS
        from app.connectors.registry import fetch_release
        class FixtureAdapter:
            ecosystem='fixture'
            def validate(self,name,version):
                if name!='test': raise InspectionError('bad fixture identity')
            def fetch(self,fetcher,name,version): return {'name':name},b'fixture'
        register_adapter(FixtureAdapter())
        try:
            self.assertEqual(fetch_release(None,'fixture','test','1')[1],b'fixture')
            with self.assertRaises(InspectionError): fetch_release(None,'fixture','other','1')
        finally: ADAPTERS.pop('fixture')

    def test_build_adapter_cannot_disable_capability_detection(self):
        from app.diff_engine.build_adapters import BUILD_ADAPTERS
        class FixtureBuild:
            def __init__(self,artifact,source): pass
            def explain(self,path): return {'equivalence_verified':True,'explanation':'Fixture generated output'}
        BUILD_ADAPTERS.append(FixtureBuild)
        try:
            report=compare(files({'out.js':b'require("child_process").execSync("echo fixture");'}),{},True)
            self.assertIn('PROCESS_EXECUTION',report['risk_reasons'])
            self.assertFalse(report['files'][0]['build_evidence']['equivalence_verified'])
        finally: BUILD_ADAPTERS.pop()

    def test_syntax_preserves_literals_asi_and_python_indentation(self):
        self.assertTrue(equivalent(b'// comment\nconst x = 1;',b'const x=1;', '.js'))
        self.assertFalse(equivalent(b'const x="a b";',b'const x="ab";', '.js'))
        self.assertFalse(equivalent(b'function f(){return\n1}',b'function f(){return 1}', '.js'))
        self.assertFalse(equivalent(b'if x:\n y()\nz()\n',b'if x:\n y()\n z()\n', '.py'))
        self.assertFalse(equivalent(b'const =',b'const =','.js'))

    def test_comment_only_change_explained_without_whitelisting_new_code(self):
        source=files({'index.js':b'const x=1;'})
        report=compare(files({'index.js':b'// release\nconst x = 1;'}),source,True)
        self.assertEqual(report['risk_score'],0)
        self.assertTrue(report['files'][0]['syntax_evidence']['same_structure'])
        report=compare(files({'index.js':b'const x=2;'}),source,True)
        self.assertIn('UNEXPLAINED_CODE',report['risk_reasons'])

    def test_source_map_trailer_not_blanket_trust(self):
        source=files({'package.json':b'{"main":"dist/a.js","scripts":{"build":"tsc"}}','src/a.ts':b'export const x=1;'})
        artifact=files({'package.json':source['package.json'].data,'dist/a.js':b'const x=1;\n//# sourceMappingURL=a.js.map\nglobalThis.fixture=1;'})
        report=compare(artifact,source,True)
        self.assertIn('UNEXPLAINED_CODE',report['risk_reasons'])
        self.assertTrue(any(f['evidence'][0]['line']==3 for f in report['findings'] if f['rule']=='UNEXPLAINED_CODE'))

    def test_missing_tag_is_evidence_not_malware_claim(self):
        report=compare({}, {}, False, {'tag_status':'missing','reasons':['All candidate tags returned 404']})
        self.assertEqual(report['risk_reasons']['SOURCE_TAG_MISSING'],20)
        self.assertEqual(report['status'],'INCONCLUSIVE')

    def test_local_archives_are_not_registry_verified(self):
        archive=pack(files({'index.js':b'const x=1;'}))
        report=compare_archives(archive,archive)
        self.assertEqual(report['metrics']['identical_files'],1)
        self.assertFalse(report['artifact']['verified'])
        self.assertEqual(report['status'],'INCONCLUSIVE')
        with self.assertRaises(InspectionError): archive_files(archive,prefix='../bad')

    def test_wheel_layout_keeps_sibling_packages(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('demo/__init__.py','x=1')
            z.writestr('demo-1.dist-info/METADATA','Name: demo')
        found,layout=archive_files(buf.getvalue())
        self.assertIn('demo/__init__.py',found)
        self.assertFalse(layout['wrapper_stripped'])

    def test_process_boundary_and_deadline(self):
        archive=pack(files({'index.js':b'const x=1;'}))
        result=bounded_inspection('local',{'artifact':archive,'source':archive})
        self.assertTrue(result['execution_boundary']['separate_process'])
        with self.assertRaises(TimeoutError): bounded_inspection('local',{'artifact':archive,'source':archive},timeout=0)

    def test_uploaded_job_persists_and_active_upload_cannot_be_deleted(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'jobs.db'; store=JobStore(path)
            item=store.upload('fixture',pack(files({'index.js':b'void 0;'})))
            job=store.create({'kind':'local','artifact_id':item['id'],'source_id':item['id']})
            with self.assertRaises(ValueError): store.remove_upload(item['id'])
            self.assertEqual(JobStore(path).read_upload(item['id']),store.read_upload(item['id']))
            self.assertEqual(JobStore(path).get(job['id'])['state'],'queued')

    def test_local_api_complete_and_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'jobs.db'
            archive=pack(files({'index.js':b'void 0;'}))
            with TestClient(create_app(path)) as client:
                upload=client.post('/api/uploads?label=test',content=archive)
                self.assertEqual(upload.status_code,201)
                uid=upload.json()['id']
                response=client.post('/api/comparisons',json={'artifact_id':uid,'source_id':uid})
                self.assertEqual(response.status_code,202)
                identity=response.json()['id']
                for _ in range(100):
                    job=client.get('/api/scans/'+identity).json()
                    if job['state'] in ('completed','failed'): break
                    time.sleep(.1)
                self.assertEqual(job['state'],'completed',job)
                self.assertEqual(client.delete('/api/uploads/'+uid).status_code,204)
            with TestClient(create_app(path)) as client:
                saved=client.get('/api/scans/'+identity).json()
                self.assertEqual(saved['result']['metrics']['identical_files'],1)
                self.assertEqual(client.get('/api/scans').json()['total'],1)
