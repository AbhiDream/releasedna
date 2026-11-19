"""Deterministic findings. No untrusted imports, builds, subprocesses or AI scoring."""
import difflib
import json
import re
import math
from collections import Counter
from pathlib import PurePosixPath
from app.diff_engine.omissions import Omissions
from app.diff_engine.build_adapters import BuildContext
from app.diff_engine.metadata import explain_metadata, manifest_cleanup
from app.diff_engine.syntax import (ESCAPES_PER_KB, MIN_ESCAPES, equivalent, code_after_map,
                                   escape_density, regex_exec_only_addition)
from app.diff_engine.javascript_patterns import OBFUSCATION_RULES

CLEAN_MEANING = 'No suspicious differences detected within the available analysis scope.'

CAPABILITIES = {
    'PROCESS_EXECUTION': (35, r'\b(?:child_process|execSync|spawnSync|subprocess|os\.system|Popen)\b'),
    'NETWORK_ACCESS': (15, r'\b(?:fetch\s*\(|https?\.(?:get|request)|requests\.|urllib\.|socket\.)'),
    'DYNAMIC_EXECUTION': (35, r'(?<![\w.$])(?:eval|exec|Function)\s*\('),
    'ENCODED_PAYLOAD': (25, r'(?:fromCharCode|atob\s*\(|b64decode|[A-Za-z0-9+/]{300,}={0,2})'),
    'SHELL_PIPELINE': (30, r'(?m)(?:\b(?:curl|wget|base64|xz|gzip|sed|tr)\b[^\n]{0,180}\|\s*(?:sh|bash|eval)\b|\b(?:m4_esyscmd|m4_syscmd)\s*\(|\b(?:sh|bash)\s+-c\b)'),
}
OBFUSCATION = {
    # Heuristics describe observable source patterns, not intent or maliciousness.
    'OBFUSCATED_DYNAMIC_EXECUTION': (40, r'''(?ix)(?:(?<![\w.$])(?:eval|Function)\s*\(\s*(?:[\w$]+\s*\+\s*|["'][^"']{1,120}["']\s*\+\s*){1,6}|[\w$.]+\s*\[\s*["'](?:ev|Fun)["']\s*\+\s*["'](?:al|ction)["']\s*\]\s*\(|\bthis\s*\[\s*[\w$]+\s*\]\s*\()'''),
    'OBFUSCATED_MODULE_LOAD': (30, r'''(?ix)(?:\b(?:require|import)\s*\(\s*(?:["']\\x[0-9a-f]{2}|["']\\u00[0-9a-f]{2})|[\w$.]+\s*\[\s*["']req["']\s*\+\s*["']uire["']\s*\]\s*\()'''),
    'BROWSER_API_HOOK': (25, r'''(?ix)\b(?:window|globalThis|self)\s*\.\s*(?:fetch|XMLHttpRequest|WebSocket)\s*=\s*(?:async\s*)?(?:function\b|\([^;]{0,300}=>)'''),
    'OBFUSCATOR_IDENTIFIER': (15, r'''(?ix)(?<![\w$])(?:var|let|const)\s+_0x[0-9a-f]+\b(?=\s*=\s*(?:\[|function\b))|(?<![\w$])_0x[0-9a-f]+\s*=\s*(?:\[|function\b)'''),
}
if set(OBFUSCATION) | {'ESCAPE_DENSITY'} != set(OBFUSCATION_RULES):
    raise RuntimeError('Obfuscation rule registry and detectors disagree')
CODE = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py', '.sh', '.ps1', '.bat', '.cmd'}
COMPRESSED_SUFFIXES = {'.gz','.br','.wasm','.woff','.woff2','.ttf','.otf','.eot'}
COMPRESSED_MAGICS = (b'\x1f\x8b',b'\x00asm',b'wOFF',b'wOF2',b'OTTO',b'\x00\x01\x00\x00',
                     b'PK\x03\x04',b'BZh',b'\xfd7zXZ\x00',b'Rar!\x1a\x07',b'7z\xbc\xaf\x27\x1c')


def known_compressed_asset(path,data):
    return PurePosixPath(path.lower()).suffix in COMPRESSED_SUFFIXES or data.startswith(COMPRESSED_MAGICS)


def text(data):
    try:
        value = data.decode('utf-8')
        return None if '\x00' in value else value
    except UnicodeError:
        return None


def compare(artifact, source, source_corroborated, source_context=None):
    rows, findings, limitations = [], [], []
    omissions = Omissions(artifact, source)
    generated = BuildContext(artifact, source)
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
        syntax_match = bool(s and is_code and a.executable==s.executable and equivalent(a.data,s.data,suffix))
        if syntax_match:
            row.update(classification='expected',explanation='Parsed syntax matches after excluding comments and source locations; literal values and program structure are retained.')
            row['syntax_evidence']={'parser':'python-ast' if suffix=='.py' else 'tree-sitter-javascript','same_structure':True,'limitation':'Syntax comparison is not build provenance verification.'}
        trailer=code_after_map(a.data,suffix)
        if trailer and (not s or not code_after_map(s.data,suffix)):
            finding(row,'UNEXPLAINED_CODE',15,'Executable statements follow the source-map trailer; matching embedded sources do not account for these statements.',trailer)
        # Non-code build macros and disguised blobs can carry executable text too.
        # Inspect a byte-preserving view of binary data without executing or decompressing it.
        scan_text = at if at is not None else a.data.decode('latin-1')
        old_text = st if st is not None else (s.data.decode('latin-1') if s else '')
        if scan_text and not syntax_match:
            rules = list(CAPABILITIES.items()) + list(OBFUSCATION.items())
            for rule, (points, pattern) in rules:
                old_count = len(re.findall(pattern, old_text or ''))
                new_matches = list(re.finditer(pattern, scan_text))
                if len(new_matches) > old_count:
                    evidence = [{'line': scan_text.count('\n', 0, m.start()) + 1,
                                 'byte_offset': len(scan_text[:m.start()].encode('utf-8')) if at is not None else m.start(),
                                 'text': scan_text[max(0,m.start()-60):m.end()+160]} for m in new_matches[:8]]
                    message = ('Specific obfuscation or browser-hook pattern; static heuristic, not proof of malicious intent.'
                               if rule in OBFUSCATION else
                               'New or increased capability indicator; static heuristic, not proof of malicious intent.')
                    finding(row, rule, points, message, evidence)
            if at is not None and s and re.sub(r'\s+', '', at) == re.sub(r'\s+', '', st or ''):
                # Whitespace can be semantic in Python and inside strings; do not claim equivalence.
                row['explanation'] = 'Text differs only in whitespace; semantic equivalence is not assumed.'
        if at is not None and suffix in {'.js','.mjs','.cjs','.jsx','.ts','.tsx'} and not path.lower().endswith('.d.ts'):
            current_density=escape_density(a.data,path,suffix)
            previous_density=escape_density(s.data,path,suffix) if s else {'eligible':True,'count':0,'per_kb':0.0,'evidence':[]}
            if current_density is None or previous_density is None:
                limitations.append(f'{path}: JavaScript escape-density analysis skipped because syntax could not be parsed within budget')
            elif current_density['eligible'] and previous_density['eligible']:
                row['escape_density']={'artifact_escapes':current_density['count'],'source_escapes':previous_density['count'],
                                       'artifact_per_kb':round(current_density['per_kb'],3),'threshold_per_kb':ESCAPES_PER_KB,
                                       'minimum_escapes':MIN_ESCAPES,'scope':'parsed string literals and template string fragments'}
                if (current_density['count']>previous_density['count'] and current_density['count']>=MIN_ESCAPES
                        and current_density['per_kb']>=ESCAPES_PER_KB):
                    finding(row,'ESCAPE_DENSITY',20,'Dense new hex/unicode escapes in parsed JavaScript strings; static obfuscation heuristic, not proof of malicious intent.',
                            current_density['evidence'])
        if s and is_code and suffix in {'.js','.mjs','.cjs'} and not row['finding_ids'] and regex_exec_only_addition(a.data,s.data,suffix):
            row.update(classification='expected',explanation='Only isolated RegExp.prototype.exec calls with string-literal arguments were added; this is not dynamic code execution.')
        if len(a.data) >= 1024:
            def entropy(data):
                return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()) if data else 0
            current_entropy = entropy(a.data)
            previous_entropy = entropy(s.data) if s else 0
            row['entropy'] = {'artifact_bits_per_byte': round(current_entropy, 4), 'source_bits_per_byte': round(previous_entropy, 4)}
            if known_compressed_asset(path,a.data):
                row['entropy_rule_skipped']='Recognized compressed, WebAssembly, or font format by extension/magic; entropy alone is not scored.'
            elif current_entropy >= 7.5 and (not s or current_entropy - previous_entropy >= .5):
                finding(row, 'HIGH_ENTROPY_CHANGE', 15, 'New high-entropy content; compression/encryption may be legitimate. Inspect the source difference.', [row['entropy']])
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
                cleanup=manifest_cleanup(ap,sp)
                if cleanup and not row['finding_ids']:
                    row.update(classification='expected',explanation=cleanup)
            except (ValueError, TypeError, AttributeError):
                finding(row, 'INVALID_MANIFEST', 20, 'Package manifest cannot be compared as a JSON object')
        if row['classification']=='unexplained' and known_compressed_asset(path,a.data):
            row.update(classification='generated_unverified',explanation='Recognized compressed, WebAssembly, or font asset; entropy is not scored alone, and binary contents/provenance remain unverified.')
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
            metadata_explanation = explain_metadata(path,a.data,generated) if state=='added' and not is_code else None
            if metadata_explanation:
                row.update(classification='expected',explanation=metadata_explanation)
            elif state == 'added' and (path == 'PKG-INFO' or '.egg-info/' in path) and not is_code:
                row.update(classification='expected', explanation='Standard source-distribution metadata, not executable code.')
            elif is_code and not row['finding_ids']:
                finding(row, 'UNEXPLAINED_CODE', 15, 'Code has no exact source match; may be build output or a modification requiring review.', added_lines[:12])
            elif (suffix in {'.md','.rst'} or (suffix=='.txt' and (path.lower().startswith(('docs/','doc/')) or PurePosixPath(path).stem.lower() in {'readme','changelog','license','authors','contributing'}))) and path not in omissions.entrypoints and path not in omissions.runtime and not a.executable and not row['finding_ids']:
                row.update(classification='expected',explanation='Documentation/text difference without a new capability indicator; contents and hash remain available for review.')
            else:
                finding(row, 'UNEXPLAINED_NONCODE', 10, 'Non-code file added or modified without a validated packaging explanation; may be legitimate, requires review.', added_lines[:12] or [{'artifact_sha256':a.sha256, 'source_sha256':s.sha256 if s else None, 'size_bytes':len(a.data)}])
    if source_context and source_context.get('tag_status')=='missing':
        findings.append({'id':f'F{len(findings)+1:04}','rule':'SOURCE_TAG_MISSING','points':20,'artifact_path':None,'source_path':None,'message':'None of the supported release tag candidates exists. Source identity remains unverified.','evidence':source_context.get('reasons',[]),'diff':''})
    # A rule contributes once per scan, preventing large packages from inflating scores by file count.
    reasons = {f['rule']: f['points'] for f in findings}
    score = min(100, sum(reasons.values()))
    unresolved = any(r['classification'] in ('unexplained', 'generated_unverified') or r.get('build_evidence') for r in rows)
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
