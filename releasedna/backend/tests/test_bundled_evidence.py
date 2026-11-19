import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.api.main import evidence_path
from app.bundle_evidence import bundle


class BundledEvidenceTests(unittest.TestCase):
    def test_bundled_evidence_survives_empty_data_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'evidence').mkdir()
            (root / 'evidence/evaluation.html').write_text('recorded')
            with patch('app.api.main.ROOT', root):
                self.assertEqual(evidence_path('evaluation.html').read_text(), 'recorded')
                (root / 'data').mkdir()
                (root / 'data/evaluation.html').write_text('new run')
                self.assertEqual(evidence_path('evaluation.html').read_text(), 'new run')

    def test_snapshot_fingerprint_mismatch_fails_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'evaluation.json').write_text(json.dumps({'detector_sha256': 'wrong'}))
            with self.assertRaisesRegex(ValueError, 'does not match'):
                bundle(tmp)
