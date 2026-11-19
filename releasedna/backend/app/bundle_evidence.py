"""Render recorded public evaluations and run the offline structural corpus."""
import json
from pathlib import Path

from app.adversarial_corpus import run
from app.diff_engine.fingerprint import detector_fingerprint
from app.evaluation import write_reports


def bundle(directory):
    directory = Path(directory)
    for name in ('evaluation', 'fresh-evaluation'):
        path = directory / (name + '.json')
        result = json.loads(path.read_text(encoding='utf-8'))
        if result.get('detector_sha256') != detector_fingerprint():
            raise ValueError('Recorded evaluation does not match the bundled detector')
        # Preserve original timestamps, counts, misses and false alarms.
        write_reports(result, path)
        html = path.with_suffix('.html')
        content = html.read_text(encoding='utf-8')
        content = content.replace('<h1>Detection, with receipts.</h1>', '<h1>Detection, with receipts.</h1><p><strong>Recorded evaluation snapshot.</strong> This report retains its original run date below; deploying this image does not rerun the public-release evaluation.</p>')
        html.write_text(content, encoding='utf-8')
    run(directory / 'adversarial.json')


if __name__ == '__main__':
    bundle(Path(__file__).resolve().parents[2] / 'evidence')
