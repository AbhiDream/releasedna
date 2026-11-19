import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.contributor_evaluation import MANIFEST, PINNED_DETECTOR, load_manifest, detection_evidence, run, summarize, write_report
from app.diff_engine.fingerprint import detector_fingerprint


class ContributorEvaluationTests(unittest.TestCase):
    def test_baseline_alert_and_unrelated_rule_are_not_detection(self):
        case = {'expected_rule': 'MISSING_ENTRYPOINT', 'expected_path': 'lib/helper.js'}
        matching = {'id': 'F1', 'rule': 'MISSING_ENTRYPOINT', 'artifact_path': None, 'source_path': 'lib/helper.js'}
        self.assertEqual(detection_evidence(case, {'findings': [matching]}, {'findings': [matching]}), [])
        unrelated = {**matching, 'source_path': 'lib/other.js'}
        self.assertEqual(detection_evidence(case, {'findings': []}, {'findings': [unrelated]}), [])
        self.assertEqual(detection_evidence(case, {'findings': []}, {'findings': [matching]}), ['F1'])

    def test_errors_misses_and_abstentions_retained(self):
        rows = [
            {'label': 'tampered', 'detected': True, 'report': {'status': 'REVIEW'}},
            {'label': 'tampered', 'detected': False, 'report': {'status': 'INCONCLUSIVE'}},
            {'label': 'benign', 'alerted': True, 'report': {'status': 'REVIEW'}},
            {'label': 'benign', 'alerted': False, 'report': {'status': 'INCONCLUSIVE'}},
            {'label': 'tampered', 'error': 'fixture failed'}]
        result = summarize(rows)
        self.assertEqual((result['TP'], result['FN'], result['FP'], result['TN']), (1, 1, 1, 1))
        self.assertEqual((result['TPR'], result['FPR']), (.5, .5))
        self.assertEqual((result['errors'], result['inconclusive']), (1, 2))
        self.assertEqual(result['errors_by_label']['tampered'], 1)
        self.assertIsNone(summarize([])['TPR'])
        self.assertIsNone(summarize([])['FPR'])

    def test_input_tampering_duplicate_ids_and_invalid_schema_fail(self):
        original = json.loads(MANIFEST.read_text(encoding='utf-8'))
        tampered = copy.deepcopy(original)
        tampered['cases'][0]['artifact']['package.json']['text'] += ' '
        duplicate = copy.deepcopy(original)
        duplicate['cases'][1]['id'] = duplicate['cases'][0]['id']
        missing = copy.deepcopy(original)
        missing['cases'][0].pop('expected_rule')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'cases.json'
            for invalid in (tampered, duplicate, missing, {'schema_version': 2}):
                path.write_text(json.dumps(invalid), encoding='utf-8')
                with self.assertRaises(ValueError):
                    load_manifest(path)

    def test_results_repeat_and_detector_change_is_rejected(self):
        current = detector_fingerprint()
        with patch('app.contributor_evaluation.PINNED_DETECTOR', current):
            first, second = run(), run()
        self.assertEqual(first['cases'], second['cases'])
        self.assertEqual(first['metrics'], second['metrics'])
        with patch('app.contributor_evaluation.detector_fingerprint', return_value='changed'), \
             patch('app.contributor_evaluation.PINNED_DETECTOR', current):
            with self.assertRaisesRegex(ValueError, 'Detector changed'):
                run()

    def test_inspection_failures_never_become_correct_classifications(self):
        def broken(*args):
            raise RuntimeError('controlled analysis failure')
        with patch('app.contributor_evaluation.PINNED_DETECTOR', detector_fingerprint()):
            result = run(comparator=broken)
        self.assertEqual(result['metrics']['errors'], 12)
        self.assertEqual(result['metrics']['evaluated'], 0)
        self.assertIsNone(result['metrics']['TPR'])
        self.assertIsNone(result['metrics']['FPR'])
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'report.json'
            write_report(result, output)
            self.assertIn('ERROR', output.with_suffix('.md').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
