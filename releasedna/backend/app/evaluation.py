"""Reproducible capture/replay harness. Downloaded artifacts are never installed or run."""
import argparse
import hashlib
import json
import html
from datetime import datetime, timezone
from pathlib import Path
from app.connectors.registry import fetch_release
from app.core.safety import Fetcher, inspect_archive
from app.source_resolver.resolve import resolve
from app.diff_engine.compare import compare
from app.evaluation_fixtures import pack, tampered_cases, benign_controls

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / 'backend/evaluation/corpus.json'
CACHE = ROOT / 'data/evaluation-cache'


def case_id(case):
    return f"{case['ecosystem']}-{case['name'].replace('/', '_').replace('@', '')}-{case['version']}"


class RecordingFetcher(Fetcher):
    def __init__(self):
        super().__init__()
        self.source_archive = None

    def get(self, url, *args, **kwargs):
        result = super().get(url, *args, **kwargs)
        if url.startswith('https://codeload.github.com/'):
            self.source_archive = result
        return result


def capture(case, cache=CACHE):
    folder = cache / case_id(case)
    folder.mkdir(parents=True, exist_ok=True)
    fetcher = RecordingFetcher()
    try:
        release, blob = fetch_release(fetcher, case['ecosystem'], case['name'], case['version'])
        inspect_archive(blob)
        source_info, _ = resolve(fetcher, release)
        if fetcher.source_archive is None:
            raise ValueError('Source resolution yielded no archive: ' + '; '.join(source_info['reasons']))
        (folder / 'artifact.tar.gz').write_bytes(blob)
        (folder / 'source.tar.gz').write_bytes(fetcher.source_archive)
        record = {'release': release, 'source': source_info, 'captured_at': datetime.now(timezone.utc).isoformat(),
                  'artifact_sha256': hashlib.sha256(blob).hexdigest(),
                  'source_sha256': hashlib.sha256(fetcher.source_archive).hexdigest()}
        (folder / 'metadata.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
        return record
    finally:
        fetcher.close()


def load_case(case, cache=CACHE):
    folder = cache / case_id(case)
    record = json.loads((folder / 'metadata.json').read_text(encoding='utf-8'))
    archives = {}
    for side in ('artifact', 'source'):
        blob = (folder / f'{side}.tar.gz').read_bytes()
        if hashlib.sha256(blob).hexdigest() != record[side + '_sha256']:
            raise ValueError('Cached archive digest mismatch: ' + side)
        if side == 'artifact':
            algorithm, digest = record['release']['artifact']['digest'].split(':', 1)
            if hashlib.new(algorithm, blob).hexdigest() != digest:
                raise ValueError('Cached artifact no longer matches captured registry digest')
        archives[side] = inspect_archive(blob)
    directory = record['release'].get('directory')
    if directory:
        prefix = directory.rstrip('/') + '/'
        archives['source'] = {p[len(prefix):]: f for p,f in archives['source'].items() if p.startswith(prefix)}
    return record, archives['artifact'], archives['source']


def fraction(numerator, denominator):
    return {'numerator': numerator, 'denominator': denominator,
            'rate': numerator / denominator if denominator else None}


def summarize(public, tampered, controls):
    available = [r for r in public if 'report' in r]
    positives = [r for r in tampered if 'report' in r]
    controls_ok = [r for r in controls if 'report' in r]
    return {
        'public_total': len(public), 'public_evaluated': len(available), 'public_errors': len(public)-len(available),
        'public_alert_rate': fraction(sum(bool(r['report']['findings']) for r in available), len(available)),
        'public_inconclusive_rate': fraction(sum(r['report']['status']=='INCONCLUSIVE' for r in available), len(available)),
        'public_clean_rate': fraction(sum(r['report']['status']=='CLEAN' for r in available), len(available)),
        'tampered_detection_rate': fraction(sum(r['detected'] for r in positives), len(positives)),
        'tampered_total': len(tampered), 'tampered_errors': len(tampered)-len(positives),
        'benign_control_alert_rate': fraction(sum(bool(r['report']['findings']) for r in controls_ok), len(controls_ok)),
        'benign_control_errors': len(controls)-len(controls_ok),
        'public_splits': {split: {
            'alert_rate': fraction(sum(bool(r['report']['findings']) for r in available if r['case']['split']==split), sum(r['case']['split']==split for r in available)),
            'inconclusive': sum(r['report']['status']=='INCONCLUSIVE' for r in available if r['case']['split']==split),
            'errors': sum('report' not in r for r in public if r['case']['split']==split)
        } for split in ('development','holdout')},
        'definitions': {
            'public_alert_rate': 'Proxy false-positive rate: presumed-benign public releases with any suspicious finding / successfully evaluated public releases. These releases are not independently certified benign.',
            'tampered_detection_rate': 'Fixture recall: a NEW finding with the preregistered rule AND exact modified path, beyond its unmodified baseline. Known-gap cases remain in the denominator.',
            'inconclusive': 'Abstention, never counted as CLEAN; can coexist with suspicious findings.',
            'errors': 'Retrieval/inspection failures reported separately, never counted as correct classifications.'}}


def synthetic_results():
    bases = {}
    for name, version in [('is-number','7.0.0'), ('mitt','3.0.1')]:
        record, artifact, source = load_case({'ecosystem':'npm','name':name,'version':version})
        bases[name] = (record, artifact, source)
    results = []
    for case in tampered_cases(bases['is-number'][1], bases['mitt'][1]):
        record, original, source = bases[case['base']]
        original_report = compare(original, source, record['source']['identity_corroborated'])
        blob = pack(case['files'])
        report = compare(inspect_archive(blob), inspect_archive(pack(source)), record['source']['identity_corroborated'])
        fingerprint = lambda f: (f['rule'], f['artifact_path'] or f['source_path'])
        baseline = {fingerprint(f) for f in original_report['findings']}
        supporting = [f for f in report['findings'] if fingerprint(f) == (case['expected_rule'], case['target']) and fingerprint(f) not in baseline]
        results.append({k:v for k,v in case.items() if k!='files'} | {
            'ground_truth': 'harmless tampered fixture', 'detected': bool(supporting),
            'supporting_finding_ids': [f['id'] for f in supporting], 'report': report,
            'provenance': {'base_package': record['release']['name'], 'base_version': record['release']['version'],
                           'base_artifact_digest': record['release']['artifact']['digest'],
                           'modified_artifact_sha256':hashlib.sha256(blob).hexdigest(),
                           'modified_artifact_registry_verified':False,
                           'source_commit':record['source']['commit']}})
    controls = []
    for identity, artifact, source in benign_controls(bases['is-number'][1]):
        report = compare(inspect_archive(pack(artifact)), inspect_archive(pack(source)), True)
        controls.append({'id':identity, 'ground_truth':'controlled benign transformation; synthetic, not registry release', 'report':report})
    return results, controls


def percent(value):
    return 'not measured' if value['rate'] is None else f"{value['numerator']}/{value['denominator']} ({100*value['rate']:.1f}%)"


def write_reports(result, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    metrics = result['metrics']
    lines = ['# ReleaseDNA detector evaluation', '', f"Generated: {result['generated_at']} | Engine: {result['engine_version']}", '',
             'Small convenience sample; public releases are presumed benign, not malware-free ground truth. No package code was executed.', '',
             '| Measure | Result |', '| --- | --- |',
             f"| Harmless tampering detected (exact rule + path) | {percent(metrics['tampered_detection_rate'])} |",
             f"| Public-release alert rate (false-positive proxy) | {percent(metrics['public_alert_rate'])} |",
             f"| Public releases inconclusive | {percent(metrics['public_inconclusive_rate'])} |",
             f"| Public releases CLEAN | {percent(metrics['public_clean_rate'])} |",
             f"| Controlled benign fixtures alerted | {percent(metrics['benign_control_alert_rate'])} |",
             f"| Public retrieval/analysis errors | {metrics['public_errors']} |", '',
             'INCONCLUSIVE is an abstention, not a successful clean classification. Detection requires the expected rule at the mutated path, not an unrelated baseline alert.', '',
             '## Public releases', '', '| Package | Split | Verdict | Findings | Generated outputs awaiting verification |', '| --- | --- | --- | --- | --- |']
    for row in result['public_releases']:
        case, report = row['case'], row.get('report')
        lines.append(f"| {case['ecosystem']}:{case['name']}@{case['version']} | {case['split']} | {report['status'] if report else 'ERROR'} | {len(report['findings']) if report else row['error']} | {len(report.get('unverified_generated_outputs',[])) if report else '—'} |")
    lines += ['', '## Harmless tampering cases', '', '| Fixture | Expected evidence | Detected | Verdict |', '| --- | --- | --- | --- |']
    for row in result['tampered_fixtures']:
        lines.append(f"| {row['id']} | {row['expected_rule']} at `{row['target']}` | {'YES' if row['detected'] else 'NO — coverage gap'} | {row['report']['status']} |")
    lines += ['', '## Limits', '',
              '- `quiet-generated-modification` is intentionally included: signature-free emitted-code changes can escape current rules. It is a false negative for detection, although the scan remains INCONCLUSIVE rather than CLEAN.',
              '- Source maps and build declarations explain why output exists; they do not prove emitted-code equivalence. Matching maps never disable capability checks.',
              '- Original development/holdout labels are historical. Both sets informed version 0.1.3; this reused corpus is not a fresh independent holdout.',
              '- Cases are pinned historical versions and a convenience sample, not a claim about current ecosystem-wide prevalence or recall.',
              '- No real malware corpus was used. Mutations are harmless text/metadata and are never executed.',
              '- Full path-level evidence, diffs, hashes, source matching and error reasons are in the sibling JSON report.']
    output.with_suffix('.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    # Standalone HTML uses escaping for every value originating in artifacts or metadata.
    esc = lambda v: html.escape(str(v))
    cards = []
    for group, rows in [('Public releases',result['public_releases']), ('Harmless tampering',result['tampered_fixtures']), ('Benign controls',result['benign_controls'])]:
        cards.append('<h2>'+esc(group)+'</h2>')
        for row in rows:
            case = row.get('case', {})
            title = row.get('id') or f"{case.get('ecosystem')}:{case.get('name')}@{case.get('version')}"
            report = row.get('report')
            if not report:
                cards.append('<details><summary>'+esc(title)+' · ERROR</summary><p>'+esc(row['error'])+'</p></details>')
                continue
            verdict = report['status']
            label = ' · '+('DETECTED' if row['detected'] else 'MISSED — coverage gap') if 'detected' in row else ''
            block = '<details><summary>'+esc(title+' · '+verdict+label)+'</summary>'
            block += '<p>'+esc(row.get('mutation', case.get('style',row.get('ground_truth',''))))+'</p>'
            block += '<p>'+esc(f"Risk score {report['risk_score']}; {len(report['findings'])} findings")+'</p>'
            for finding in report['findings']:
                block += '<article><h3>'+esc(finding['rule']+' · '+str(finding['artifact_path'] or finding['source_path']))+'</h3><p>'+esc(finding['message'])+'</p><pre>'+esc(json.dumps(finding['evidence'],indent=2))+'</pre><pre>'+esc(finding['diff'])+'</pre></article>'
            generated = [r for r in report['files'] if r.get('build_evidence') or r.get('source_map_evidence')]
            for file in generated:
                block += '<h3>'+esc(file['path']+' · '+file['classification'])+'</h3><p>'+esc(file['explanation'])+'</p><pre>'+esc(json.dumps(file.get('build_evidence') or file.get('source_map_evidence'),indent=2))+'</pre>'
            block += '<details><summary>Full scan evidence</summary><pre>'+esc(json.dumps(report,indent=2))+'</pre></details></details>'
            cards.append(block)
    dashboard = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ReleaseDNA — detector evaluation</title><style>body{font:16px/1.6 system-ui;background:#0b1220;color:#e2e8f0;max-width:1120px;margin:auto;padding:28px}a{color:#6ee7ce}h1{font-size:40px}h2{margin-top:40px}.metrics{display:flex;gap:16px;flex-wrap:wrap}.metric,details{background:#142137;border:1px solid #334155;border-radius:12px;padding:20px;margin:12px 0}.metric{flex:1;min-width:230px}.metric strong{display:block;font-size:30px;color:#6ee7ce}summary{cursor:pointer;font-weight:650}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#091321;padding:16px}article{border-left:3px solid #fbbf24;padding:0 16px}p{color:#c4cfe0}</style><a href="/">ReleaseDNA scan console</a><h1>Detection, with receipts.</h1><p>Real public releases. Harmless tampered copies. Explicit coverage gaps.</p><div class="metrics">'
    for label,key in [('Tampering detected','tampered_detection_rate'),('Public-release alerts','public_alert_rate'),('Public releases inconclusive','public_inconclusive_rate')]:
        dashboard += '<div class="metric"><strong>'+esc(percent(metrics[key]))+'</strong>'+esc(label)+'</div>'
    dashboard += '</div><p>Public-release alerts are a false-positive proxy on presumed-benign samples. Inconclusive is not clean. This small corpus does not establish ecosystem-wide accuracy.</p><p>'+esc(result.get('evaluation_design',''))+'</p><p>Known miss: a quiet generated-code modification has no matching capability signature. Matching source maps do not prove bundle integrity.</p><p>Generated '+esc(result['generated_at'])+' · engine '+esc(result['engine_version'])+' · <a href="/api/evaluation">Download complete JSON evidence</a></p>'+''.join(cards)+'</html>'
    output.with_suffix('.html').write_text(dashboard, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['capture', 'run'])
    parser.add_argument('--split', choices=['development', 'holdout', 'all'], default='all')
    parser.add_argument('--output', type=Path, default=ROOT / 'data/evaluation.json')
    parser.add_argument('--include-fixtures', action='store_true')
    args = parser.parse_args()
    corpus = json.loads(CORPUS.read_text())
    cases = [c for c in corpus['public_releases'] if args.split == 'all' or c['split'] == args.split]
    results = []
    for case in cases:
        try:
            if args.command == 'capture':
                capture(case)
            record, artifact, source = load_case(case)
            report = compare(artifact, source, record['source']['identity_corroborated'])
            results.append({'case': case, 'provenance': record, 'report': report})
            print(f"{case_id(case)}: {report['status']} | {len(report['findings'])} findings | {report['risk_score']}", flush=True)
        except Exception as exc:
            results.append({'case': case, 'error': f'{type(exc).__name__}: {exc}'})
            print(f'{case_id(case)}: ERROR {exc}', flush=True)
    if args.include_fixtures:
        tampered, controls = synthetic_results()
        metrics = summarize(results, tampered, controls)
        payload = {'schema_version':1, 'engine_version':'0.1.3', 'generated_at':datetime.now(timezone.utc).isoformat(),
                   'corpus_sha256':hashlib.sha256(CORPUS.read_bytes()).hexdigest(), 'metrics':metrics,
                   'detector_sha256':hashlib.sha256(b''.join((Path(__file__).parent/'diff_engine'/name).read_bytes() for name in ('compare.py','generated.py','omissions.py','metadata.py'))).hexdigest(),
                   'evaluation_design':'Original development/holdout labels retained for historical comparison. Both sets informed version 0.1.3; this is now a reused development corpus, not a fresh holdout.',
                   'public_releases':results, 'tampered_fixtures':tampered, 'benign_controls':controls}
        write_reports(payload,args.output)
        print(json.dumps(metrics, indent=2))
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({'cases': results}, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
