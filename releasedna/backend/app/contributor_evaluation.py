import argparse
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from app.core.safety import File, inspect_archive
from app.diff_engine.compare import compare
from app.diff_engine.fingerprint import detector_fingerprint
from app.evaluation_fixtures import pack

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = ROOT / 'backend/evaluation/contributor-corpus.json'
PREREGISTRATION_URL = 'https://github.com/kirtisihag-1808/releasedna/commit/36df57d579e6c8438afd533d1a9d18526ea17a33'

REQUIRED_FIELDS = {'id', 'ecosystem', 'ground_truth', 'base_identity', 'mutation', 'expected_rule', 'expected_path', 'source_files', 'artifact_files'}


def fraction(num, den):
    return {'numerator': num, 'denominator': den, 'rate': num / den if den else None}


def pct(val):
    return 'not measured' if val['rate'] is None else f"{val['numerator']}/{val['denominator']} ({100 * val['rate']:.1f}%)"


def validate_manifest(data):
    if not isinstance(data, dict) or not isinstance(data.get('cases'), list) or not data['cases']:
        raise ValueError('Manifest must contain a non-empty cases list.')
    seen = set()
    for c in data['cases']:
        missing = REQUIRED_FIELDS - set(c.keys())
        if missing:
            raise ValueError(f"Case missing required fields: {sorted(missing)}")
        if c['id'] in seen:
            raise ValueError(f"Duplicate case id: {c['id']}")
        seen.add(c['id'])
        if c['ground_truth'] == 'harmless tampered fixture' and (not c['expected_rule'] or not c['expected_path']):
            raise ValueError(f"Tampered case {c['id']} requires expected_rule and expected_path.")


def build_archive(files_map):
    wrapped = {path: File(content.encode('utf-8')) for path, content in files_map.items()}
    return pack(wrapped)


def evaluate_case(case):
    src_blob = build_archive(case['source_files'])
    art_blob = build_archive(case['artifact_files'])
    baseline_report = compare(inspect_archive(src_blob), inspect_archive(src_blob), True)
    report = compare(inspect_archive(art_blob), inspect_archive(src_blob), True)

    fp = lambda f: (f['rule'], f['artifact_path'] or f['source_path'])
    baseline_alerts = {fp(f) for f in baseline_report['findings']}
    new_findings = [f for f in report['findings'] if fp(f) not in baseline_alerts]

    is_tampered = case['ground_truth'] == 'harmless tampered fixture'
    matched = [f for f in new_findings if fp(f) == (case['expected_rule'], case['expected_path'])] if is_tampered else []

    return {
        'id': case['id'],
        'ecosystem': case['ecosystem'],
        'ground_truth': case['ground_truth'],
        'base_identity': case['base_identity'],
        'mutation': case['mutation'],
        'expected_rule': case['expected_rule'],
        'expected_path': case['expected_path'],
        'source_sha256': hashlib.sha256(src_blob).hexdigest(),
        'artifact_sha256': hashlib.sha256(art_blob).hexdigest(),
        'status': report['status'],
        'risk_score': report['risk_score'],
        'detected': bool(matched) if is_tampered else None,
        'alerted': bool(new_findings),
        'new_findings': new_findings,
        'report': report,
    }


def summarize(rows):
    ok = [r for r in rows if 'error' not in r]
    tampered = [r for r in ok if r['ground_truth'] == 'harmless tampered fixture']
    benign = [r for r in ok if r['ground_truth'] != 'harmless tampered fixture']
    tp = sum(bool(r['detected']) for r in tampered)
    fn = len(tampered) - tp
    fp = sum(bool(r['alerted']) for r in benign)
    tn = len(benign) - fp
    return {
        'total_cases': len(rows),
        'evaluated_cases': len(ok),
        'error_count': len(rows) - len(ok),
        'inconclusive_count': sum(r['status'] == 'INCONCLUSIVE' for r in ok),
        'tampered_inspected': len(tampered),
        'benign_inspected': len(benign),
        'TP': tp, 'FN': fn, 'FP': fp, 'TN': tn,
        'TPR': fraction(tp, tp + fn),
        'FPR': fraction(fp, fp + tn),
    }


def run_evaluation(corpus_path=DEFAULT_CORPUS, output_path=None):
    raw_bytes = Path(corpus_path).read_bytes()
    manifest = json.loads(raw_bytes.decode('utf-8'))
    validate_manifest(manifest)

    rows = []
    for case in manifest['cases']:
        try:
            rows.append(evaluate_case(case))
        except Exception as exc:
            rows.append({'id': case.get('id', 'unknown'), 'error': f'{type(exc).__name__}: {exc}'})

    metrics = summarize(rows)
    payload = {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'preregistration_url': PREREGISTRATION_URL,
        'manifest_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'detector_sha256': detector_fingerprint(),
        'environment': {'os': platform.platform(), 'python': sys.version.split()[0]},
        'ai_assistance': 'Manifest and harness drafted with Gemini AI assistance; executed and verified by contributor kirtisihag-1808.',
        'metrics': metrics,
        'cases': rows,
    }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding='utf-8')
        write_markdown(payload, out.with_suffix('.md'))
    return payload


def write_markdown(payload, md_path):
    m = payload['metrics']
    lines = [
        '# ReleaseDNA Independent Contributor Evaluation', '',
        f"- **Generated at:** {payload['generated_at']}",
        f"- **Preregistration commit:** {payload['preregistration_url']}",
        f"- **Manifest SHA-256:** `{payload['manifest_sha256']}`",
        f"- **Detector fingerprint:** `{payload['detector_sha256']}`",
        f"- **Environment:** {payload['environment']['os']} | Python {payload['environment']['python']}",
        f"- **AI assistance:** {payload['ai_assistance']}", '',
        '## Summary Metrics', '',
        '| Metric | Result |', '| --- | --- |',
        f"| Tampered cases inspected | {m['tampered_inspected']} |",
        f"| Benign cases inspected | {m['benign_inspected']} |",
        f"| TP / FN / FP / TN | {m['TP']} / {m['FN']} / {m['FP']} / {m['TN']} |",
        f"| True Positive Rate (TPR) | {pct(m['TPR'])} |",
        f"| False Positive Rate (FPR) | {pct(m['FPR'])} |",
        f"| Retrieval / inspection errors | {m['error_count']} |",
        f"| INCONCLUSIVE verdicts | {m['inconclusive_count']} |", '',
        '## Per-Case Results', '',
        '| Case ID | Ecosystem | Ground Truth | Expected | Verdict | Outcome |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for r in payload['cases']:
        if 'error' in r:
            lines.append(f"| `{r['id']}` | — | — | — | ERROR | {r['error']} |")
            continue
        exp = f"`{r['expected_rule']}` at `{r['expected_path']}`" if r['expected_rule'] else 'No findings'
        if r['ground_truth'] == 'harmless tampered fixture':
            outcome = 'TP (Detected)' if r['detected'] else 'FN (Missed)'
        else:
            outcome = 'FP (False Alarm)' if r['alerted'] else 'TN (Clean)'
        lines.append(f"| `{r['id']}` | {r['ecosystem']} | {r['ground_truth']} | {exp} | {r['status']} | {outcome} |")
    lines += [
        '', '## Limitations & Scope', '',
        '- Synthetic self-contained fixtures only; not organizer-supplied data or real historical malware.',
        '- Scanned archive bytes were never installed, imported, built, or executed.',
        '- AI assistance (Gemini) was used to help design the manifest and harness; all runs were executed locally.',
    ]
    md_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Run contributor evaluation manifest.')
    parser.add_argument('--corpus', type=Path, default=DEFAULT_CORPUS)
    parser.add_argument('--output', type=Path, default=ROOT / 'data/contributor-evaluation.json')
    args = parser.parse_args()
    res = run_evaluation(args.corpus, args.output)
    print(json.dumps(res['metrics'], indent=2))


if __name__ == '__main__':
    main()
