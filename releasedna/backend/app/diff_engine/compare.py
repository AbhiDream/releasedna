"""Deterministic findings. No untrusted imports, builds, subprocesses or AI scoring."""
import difflib
import json
import re
from pathlib import PurePosixPath
from app.diff_engine.omissions import Omissions
from app.diff_engine.generated import GeneratedContext

CLEAN_MEANING = 'No suspicious differences detected within the available analysis scope.'

CAPABILITIES = {
    'PROCESS_EXECUTION': (35, r'\b(?:child_process|execSync|spawnSync|subprocess|os\.system|Popen)\b'),
    'NETWORK_ACCESS': (15, r'\b(?:fetch\s*\(|https?\.(?:get|request)|requests\.|urllib\.|socket\.)'),
    'DYNAMIC_EXECUTION': (35, r'\b(?:eval|exec|Function)\s*\('),
    'ENCODED_PAYLOAD': (25, r'(?:fromCharCode|atob\s*\(|b64decode|[A-Za-z0-9+/]{300,}={0,2})'),
}
CODE = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py', '.sh', '.ps1', '.bat', '.cmd'}


def text(data):
    try:
        value = data.decode('utf-8')
        return None if '\x00' in value else value
    except UnicodeError:
        return None


def compare(artifact, source, source_corroborated):
    rows, findings, limitations = [], [], []
    omissions = Omissions(artifact, source)
    generated = GeneratedContext(artifact, source)
    if not source:
        limitations.append('Source unavailable: added files mean unmatched files, not proven additions')

    def finding(row, rule, points, message, lines=None):
        item = {'id': f'F{len(findings)+1:04}', 'rule': rule, 'points': points,
                'artifact_path': row['artifact_path'], 'source_path': row['source_path'],
                'message': message, 'evidence': lines or [], 'diff': row.get('diff', '')}
        findings.append(item)
        row['finding_ids'].append(item['id'])
        row['classification'] = 'suspicious'

    for path in sorted(set(artifact) | set(source)):
        a, s = artifact.get(path), source.get(path)
        state = 'removed' if a is None else 'added' if s is None else 'identical' if a.data == s.data and a.executable == s.executable else 'changed'
        row = {'path': path, 'artifact_path': path if a else None, 'source_path': path if s else None,
               'state': state, 'classification': 'identical' if state == 'identical' else 'unexplained',
               'artifact_sha256': a.sha256 if a else None, 'source_sha256': s.sha256 if s else None,
               'finding_ids': [], 'explanation': '', 'diff': ''}
        rows.append(row)
        if state == 'identical':
            continue
        if a is None:
            decision = omissions.classify(path)
            points = decision.pop('points')
            row.update(decision)
            if points:
                finding(row, row['omission_rule'], points, row['explanation'])
            continue
        at, st = text(a.data), text(s.data) if s else ''
        added_lines = []
        if at is not None and st is not None:
            al, sl = at.splitlines(), st.splitlines()
            if len(al) + len(sl) <= 12000 and len(a.data) + (len(s.data) if s else 0) <= 256000:
                matcher = difflib.SequenceMatcher(None, sl, al, autojunk=True)
                for op, i, j, k, l in matcher.get_opcodes():
                    if op in ('replace', 'insert'):
                        added_lines.extend({'line': n + 1, 'text': al[n][:600]} for n in range(k, l))
                diff = list(difflib.unified_diff(sl, al, fromfile='source/' + path, tofile='artifact/' + path, lineterm=''))
                row['diff'] = '\n'.join(diff)[:24000]
                row['diff_truncated'] = len('\n'.join(diff)) > 24000
            else:
                row['diff_truncated'] = True
                limitations.append(f'{path}: line diff exceeds processing budget; whole-file pattern comparison used')
        suffix = PurePosixPath(path).suffix.lower()
        build_evidence = generated.explain(path)
        if build_evidence:
            row['build_evidence'] = build_evidence
            row.update(classification='generated_unverified', explanation=build_evidence['explanation'])
        is_code = suffix in CODE or a.executable
        if is_code and at is not None:
            for rule, (points, pattern) in CAPABILITIES.items():
                old_count = len(re.findall(pattern, st or ''))
                new_matches = list(re.finditer(pattern, at))
                if len(new_matches) > old_count:
                    evidence = [{'line': at.count('\n', 0, m.start()) + 1,
                                 'text': at[max(0,m.start()-60):m.end()+160]} for m in new_matches[:8]]
                    finding(row, rule, points, 'New or increased capability indicator; static heuristic, not proof of malicious intent.', evidence)
            if s and re.sub(r'\s+', '', at) == re.sub(r'\s+', '', st or ''):
                # Whitespace can be semantic in Python and inside strings; do not claim equivalence.
                row['explanation'] = 'Text differs only in whitespace; semantic equivalence is not assumed.'
        if path == 'package.json' and at is not None:
            try:
                ap = json.loads(at)
                sp = json.loads(st) if st else {}
                for hook in ('preinstall', 'install', 'postinstall', 'prepare'):
                    new, old = ap.get('scripts', {}).get(hook), sp.get('scripts', {}).get(hook)
                    if new is not None and new != old:
                        finding(row, 'INSTALL_SCRIPT_CHANGED', 45, f'{hook} changed from {old!r} to {new!r}',
                                [x for x in added_lines if hook in x['text']])
                for field in ('dependencies', 'optionalDependencies', 'peerDependencies'):
                    if ap.get(field, {}) != sp.get(field, {}):
                        finding(row, 'DEPENDENCIES_CHANGED', 25, f'{field} differs from source', added_lines[:8])
                # Only registry-added underscore metadata is explained automatically.
                stripped = {k: v for k, v in ap.items() if not k.startswith('_')}
                if s and stripped == sp and not row['finding_ids']:
                    row.update(classification='expected', explanation='Manifest differs only in JSON formatting or registry underscore metadata.')
            except (ValueError, TypeError, AttributeError):
                finding(row, 'INVALID_MANIFEST', 20, 'Package manifest cannot be compared as a JSON object')
        if a.executable and (not s or not s.executable):
            finding(row, 'EXECUTABLE_ADDED', 25, 'Executable permission is new relative to source', added_lines[:5])
        if a.data.startswith((b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe')):
            finding(row, 'BINARY_CHANGED', 30, 'New or modified native executable; build provenance required')
        if suffix == '.map' and at:
            evidence = generated.maps[path]
            row['source_map_evidence'] = evidence
            if evidence['mismatched_sources']:
                finding(row, 'SOURCEMAP_SOURCE_MISMATCH', 25, 'Embedded sources differ from repository content.', evidence['mismatched_sources'][:8])
            elif evidence['all_embedded_sources_match'] and not row['finding_ids']:
                row['classification'] = 'expected'
            row['explanation'] = ('Source-map metadata inspected without fetching references. '
                                  f"{len(evidence['matching_sources'])} embedded sources match; "
                                  f"{len(evidence['mismatched_sources'])} differ; "
                                  f"{len(evidence['unresolved_sources'])} unresolved. " + evidence['limitation'])
        if row['classification'] == 'unexplained':
            if state == 'added' and (path == 'PKG-INFO' or '.egg-info/' in path) and not is_code:
                row.update(classification='expected', explanation='Standard source-distribution metadata, not executable code.')
            elif is_code:
                finding(row, 'UNEXPLAINED_CODE', 15, 'Code has no exact source match; may be build output or a modification requiring review.', added_lines[:12])
            else:
                row['explanation'] = row['explanation'] or 'No validated packaging transformation explains this difference.'
    # A rule contributes once per scan, preventing large packages from inflating scores by file count.
    reasons = {f['rule']: f['points'] for f in findings}
    score = min(100, sum(reasons.values()))
    unresolved = any(r['classification'] in ('unexplained', 'generated_unverified') for r in rows)
    status = 'HIGH_RISK' if score >= 70 else 'REVIEW' if findings else 'CLEAN'
    if not source_corroborated or unresolved or limitations:
        status = 'INCONCLUSIVE'
    counts = {key: sum(r['state'] == key for r in rows) for key in ('identical', 'added', 'removed', 'changed')}
    metrics = {'artifact_file_count': len(artifact), 'source_file_count': len(source),
               'unique_comparison_paths': len(rows), **{key + '_files': value for key, value in counts.items()}}
    return {'status': status, 'clean_definition': CLEAN_MEANING, 'risk_score': score, 'risk_reasons': reasons,
            'suspicion_level': 'HIGH_RISK' if score >= 70 else 'REVIEW' if findings else 'NONE',
            'total_files_inspected': len(artifact) + len(source),
            'total_files_inspected_definition': 'Artifact plus source file instances; shared paths count twice. Use metrics.unique_comparison_paths for comparison rows.',
            'metrics': metrics, 'counts': counts,
            'expected_generated_differences': [r['path'] for r in rows if r['classification'] == 'expected' and r['state'] != 'removed'],
            'unverified_generated_outputs': [r['path'] for r in rows if r.get('build_evidence')],
            'findings': findings, 'files': rows, 'limitations': limitations}
