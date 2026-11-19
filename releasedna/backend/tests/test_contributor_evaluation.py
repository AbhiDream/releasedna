import tempfile
import unittest
from pathlib import Path
from app.contributor_evaluation import DEFAULT_CORPUS, run_evaluation, summarize, validate_manifest


class ContributorEvaluationTests(unittest.TestCase):
    def test_manifest_schema_and_repeatability(self):
        with tempfile.TemporaryDirectory() as tmp:
            out1 = Path(tmp) / 'run1.json'
            out2 = Path(tmp) / 'run2.json'
            r1 = run_evaluation(DEFAULT_CORPUS, out1)
            r2 = run_evaluation(DEFAULT_CORPUS, out2)
            self.assertEqual(r1['metrics'], r2['metrics'])
            self.assertEqual(r1['manifest_sha256'], r2['manifest_sha256'])
            self.assertTrue(out1.with_suffix('.md').exists())

    def test_duplicate_id_rejected(self):
        bad = {'cases': [
            {'id': 'dup', 'ecosystem': 'npm', 'ground_truth': 'benign control', 'base_identity': 'x',
             'mutation': 'y', 'expected_rule': None, 'expected_path': None, 'source_files': {}, 'artifact_files': {}},
            {'id': 'dup', 'ecosystem': 'npm', 'ground_truth': 'benign control', 'base_identity': 'x',
             'mutation': 'y', 'expected_rule': None, 'expected_path': None, 'source_files': {}, 'artifact_files': {}}
        ]}
        with self.assertRaises(ValueError):
            validate_manifest(bad)

    def test_empty_denominators_and_errors(self):
        metrics = summarize([{'id': 'err-1', 'error': 'RuntimeError: failed'}])
        self.assertEqual(metrics['error_count'], 1)
        self.assertIsNone(metrics['TPR']['rate'])
        self.assertIsNone(metrics['FPR']['rate'])


if __name__ == '__main__':
    unittest.main()
