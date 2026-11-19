import json
import tempfile
import unittest
from pathlib import Path
from app.evaluation import summarize, write_reports, load_case


class EvaluationTests(unittest.TestCase):
    def test_denominators_exclude_errors_but_keep_abstentions_and_misses(self):
        public = [
            {'case':{'split':'development'},'report':{'status':'CLEAN','findings':[]}},
            {'case':{'split':'holdout'},'report':{'status':'INCONCLUSIVE','findings':[]}},
            {'case':{'split':'holdout'},'report':{'status':'INCONCLUSIVE','findings':[{'rule':'X'}]}},
            {'case':{'split':'holdout'},'error':'offline'}]
        positives = [{'report':{},'detected':True}, {'report':{},'detected':False,'known_gap':True}]
        result = summarize(public, positives, [])
        self.assertEqual(result['public_alert_rate']['rate'], 1/3)
        self.assertEqual(result['public_inconclusive_rate']['rate'], 2/3)
        self.assertEqual(result['tampered_detection_rate']['rate'], .5)
        self.assertEqual(result['public_errors'], 1)
        self.assertEqual(result['public_splits']['holdout']['alert_rate']['rate'], .5)

    def test_empty_corpus_is_not_reported_as_zero_percent(self):
        result = summarize([], [], [])
        self.assertIsNone(result['public_alert_rate']['rate'])
        self.assertIsNone(result['tampered_detection_rate']['rate'])

    def test_report_escapes_untrusted_evidence(self):
        report = {'status':'REVIEW','risk_score':15,'files':[], 'findings':[
            {'rule':'UNEXPLAINED_CODE','artifact_path':'<script>fixture</script>', 'source_path':None,
             'message':'<img src=x onerror=alert(1)>', 'evidence':[], 'diff':'<script>alert(1)</script>'}]}
        public = [{'case':{'name':'demo','version':'1','ecosystem':'npm','split':'development','style':'fixture'},'report':report}]
        payload = {'generated_at':'test', 'engine_version':'test', 'public_releases':public,
                   'tampered_fixtures':[],'benign_controls':[], 'metrics':summarize(public,[],[])}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'report.json'
            write_reports(payload,output)
            html = output.with_suffix('.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>',html)
            self.assertIn('&lt;script&gt;',html)
            self.assertEqual(json.loads(output.read_text())['metrics']['public_alert_rate']['rate'],1)

    def test_cache_tampering_rejected_before_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)/'npm-demo-1'
            folder.mkdir()
            (folder/'metadata.json').write_text(json.dumps({'artifact_sha256':'0'*64}))
            (folder/'artifact.tar.gz').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'digest mismatch'):
                load_case({'ecosystem':'npm','name':'demo','version':'1'},Path(directory))
