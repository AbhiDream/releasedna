"""AI-assisted synthetic evaluation. Inspect fixture bytes; never execute them."""
import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from app.core.safety import File, inspect_archive, safe_path
from app.diff_engine.compare import compare
from app.diff_engine.fingerprint import detector_fingerprint
from app.evaluation_fixtures import pack

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'backend/evaluation/contributor-corpus.json'
PINNED_DETECTOR = '593bf2033947f0d0cbdb26c0fd99229643586c27a058d16df19b019f14e827ad'
PREREGISTRATION = '8d114b5'
SIDES = ('source', 'baseline', 'artifact')


def input_hash(snapshot):
    encoded = json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_manifest(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Manifest exceeds 1 MiB')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise ValueError('Expected manifest schema_version 1')
    if (value.get('detector_commit') != '3a93ae3d5b0cd7ee6fe51f5f248ac1981d142a80'
            or value.get('input_hash_format') != 'sha256-json-sorted-compact-ascii-v1'
            or not isinstance(value.get('design'), str)):
        raise ValueError('Manifest must identify the frozen detector and supported hash format')
    rows = value.get('cases')
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise ValueError('Expected 1 to 100 cases')
    identities = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not row['id'] or row['id'] in identities:
            raise ValueError('Missing or duplicate case ID')
        identities.add(row['id'])
        if not isinstance(row.get('input_sha256'), dict) or set(row['input_sha256']) != set(SIDES):
            raise ValueError('All three input hashes are required')
        if row.get('label') not in ('tampered', 'benign') or row.get('ecosystem') not in ('npm', 'pypi'):
            raise ValueError('Invalid case label/ecosystem')
        if not isinstance(row.get('description'), str) or not isinstance(row.get('origin'), str):
            raise ValueError('Case description/origin required')
        if row['label'] == 'tampered':
            if not isinstance(row.get('expected_rule'), str) or not row['expected_rule']:
                raise ValueError('Tampered case requires expected rule')
            if not isinstance(row.get('expected_path'), str):
                raise ValueError('Tampered case requires expected path')
            safe_path(row['expected_path'])
        elif row.get('expected_rule') is not None or row.get('expected_path') is not None:
            raise ValueError('Benign case cannot declare a detection target')
        for side in SIDES:
            snapshot = row.get(side)
            if not isinstance(snapshot, dict) or not snapshot or len(snapshot) > 100:
                raise ValueError('Expected 1 to 100 files in each snapshot')
            for path, entry in snapshot.items():
                safe_path(path)
                if (not isinstance(entry, dict) or set(entry) != {'text', 'executable'}
                        or not isinstance(entry['text'], str) or type(entry['executable']) is not bool
                        or len(entry['text'].encode()) > 64000):
                    raise ValueError('Invalid or oversized fixture file')
            if row.get('input_sha256', {}).get(side) != input_hash(snapshot):
                raise ValueError(f"Input digest mismatch: {row['id']}/{side}")
        if row['label'] == 'tampered' and row['expected_path'] not in set(row['source']) | set(row['artifact']):
            raise ValueError('Expected path does not exist in either comparison side')
    return value


def finding_key(finding):
    return finding['rule'], finding.get('artifact_path') or finding.get('source_path')


def detection_evidence(case, baseline, report):
    old = {finding_key(item) for item in baseline['findings']}
    expected = (case['expected_rule'], case['expected_path'])
    return [item['id'] for item in report['findings']
            if finding_key(item) == expected and finding_key(item) not in old]


def evaluate_case(case, comparator=compare):
    archives = {side: pack({path: File(entry['text'].encode(), entry['executable'])
                           for path, entry in case[side].items()}) for side in SIDES}
    files = {side: inspect_archive(blob) for side, blob in archives.items()}
    # True denotes known controlled source identity here, never a registry/provenance claim.
    baseline = comparator(files['baseline'], files['source'], True)
    report = comparator(files['artifact'], files['source'], True)
    evidence = detection_evidence(case, baseline, report) if case['label'] == 'tampered' else []
    return {'id': case['id'], 'label': case['label'], 'ecosystem': case['ecosystem'],
            'description': case['description'], 'expected_rule': case['expected_rule'],
            'expected_path': case['expected_path'], 'detected': bool(evidence),
            'alerted': bool(report['findings']), 'supporting_finding_ids': evidence,
            'archive_sha256': {side: hashlib.sha256(blob).hexdigest() for side, blob in archives.items()},
            'input_sha256': case['input_sha256'], 'baseline_report': baseline, 'report': report}


def summarize(rows):
    successful = [row for row in rows if 'report' in row]
    positives = [row for row in successful if row['label'] == 'tampered']
    negatives = [row for row in successful if row['label'] == 'benign']
    tp = sum(row['detected'] for row in positives)
    fp = sum(row['alerted'] for row in negatives)
    return {'total': len(rows), 'evaluated': len(successful), 'errors': len(rows) - len(successful),
            'TP': tp, 'FN': len(positives) - tp, 'FP': fp, 'TN': len(negatives) - fp,
            'TPR': tp / len(positives) if positives else None,
            'FPR': fp / len(negatives) if negatives else None,
            'inconclusive': sum(row['report']['status'] == 'INCONCLUSIVE' for row in successful),
            'errors_by_label': {label: sum('report' not in row and row['label'] == label for row in rows)
                                for label in ('tampered', 'benign')}}


def run(manifest_path=MANIFEST, comparator=compare):
    manifest = load_manifest(manifest_path)
    actual = detector_fingerprint()
    if actual != PINNED_DETECTOR:
        raise ValueError('Detector changed: preregister a new experiment instead of overwriting this frozen result')
    rows = []
    for case in manifest['cases']:
        try:
            rows.append(evaluate_case(case, comparator))
        except Exception as exc:
            rows.append({'id': case['id'], 'label': case['label'], 'ecosystem': case['ecosystem'],
                         'error': f'{type(exc).__name__}: {exc}'})
    return {'schema_version': 1, 'generated_at': datetime.now(timezone.utc).isoformat(),
            'design': manifest['design'], 'preregistration_commit': PREREGISTRATION,
            'detector_commit': manifest['detector_commit'], 'detector_sha256': actual,
            'manifest_sha256': hashlib.sha256(Path(manifest_path).read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
            'manifest_hash_format': 'sha256-utf8-lf',
            'environment': {'os': platform.system(), 'python': platform.python_version()},
            'scope': 'Synthetic fixtures; controlled source identity, no registry verification. No fixture code executed.',
            'metrics': summarize(rows), 'cases': rows}


def write_report(result, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('<', '&lt;').replace('>', '&gt;')
    metrics = result['metrics']
    lines = ['# AI-assisted contributor evaluation', '', result['design'], '',
             'Generated: ' + result['generated_at'], '',
             '| Measure | Result |', '| --- | --- |']
    for key in ('total', 'evaluated', 'errors', 'TP', 'FN', 'FP', 'TN', 'TPR', 'FPR', 'inconclusive'):
        value = metrics[key]
        lines.append(f'| {key} | {"Not measured" if value is None else value} |')
    lines += ['', 'TP requires the expected NEW rule at the exact path, beyond baseline findings. '
              'Errors are excluded from TPR/FPR and retained separately. INCONCLUSIVE is not CLEAN.', '',
              '| Case | Label | Outcome | Verdict | Evidence IDs |', '| --- | --- | --- | --- | --- |']
    for row in result['cases']:
        if 'report' not in row:
            outcome, verdict, evidence = 'ERROR: ' + row['error'], 'not evaluated', ''
        else:
            outcome = ('TP' if row['detected'] else 'FN') if row['label'] == 'tampered' else ('FP' if row['alerted'] else 'TN')
            verdict, evidence = row['report']['status'], ', '.join(row['supporting_finding_ids'])
        lines.append('| ' + ' | '.join(map(cell, (row['id'], row['label'], outcome, verdict, evidence))) + ' |')
    lines += ['', 'Synthetic known-rule convenience cases, not independent unseen recall or organizer validation. '
              'No detector changes were made. Sibling JSON includes complete diffs, baseline findings, hashes and errors.', '']
    output.with_suffix('.md').write_text('\n'.join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--output', type=Path, default=ROOT / 'data/contributor-evaluation.json')
    args = parser.parse_args()
    result = run(args.manifest)
    write_report(result, args.output)
    print(json.dumps(result['metrics'], indent=2))
    return 1 if result['metrics']['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
