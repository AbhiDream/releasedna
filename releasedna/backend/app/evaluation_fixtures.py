"""Harmless modifications as bytes only. None of these strings is ever executed."""
import gzip
import io
import json
import tarfile
from app.core.safety import File


def pack(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for path, value in sorted(files.items()):
            entry = tarfile.TarInfo('package/' + path)
            entry.size, entry.mtime, entry.mode = len(value.data), 0, 0o755 if value.executable else 0o644
            archive.addfile(entry, io.BytesIO(value.data))
    return gzip.compress(output.getvalue(), mtime=0)


def tampered_cases(base, mapped):
    """Descriptors declare expected evidence before any detector invocation."""
    cases = []
    def add(identity, origin, files, target, rule, explanation, known_gap=False):
        cases.append({'id': identity, 'base': origin, 'files': files, 'target': target,
                      'expected_rule': rule, 'mutation': explanation, 'known_gap': known_gap})
    changed = dict(base)
    manifest = json.loads(changed['package.json'].data)
    manifest.setdefault('scripts', {})['postinstall'] = 'node -e "void 0"'
    changed['package.json'] = File(json.dumps(manifest, indent=2).encode())
    add('added-install-hook', 'is-number', changed, 'package.json', 'INSTALL_SCRIPT_CHANGED', 'Add harmless postinstall command; never run it.')
    changed = dict(base)
    changed['index.js'] = File(changed['index.js'].data + b'\nmodule.exports = function () { return true; };\n')
    add('modified-runtime-source', 'is-number', changed, 'index.js', 'UNEXPLAINED_CODE', 'Override the exported function with a harmless constant result.')
    for identity, path, data, rule, description in [
        ('added-process-indicator', 'helper.js', b"require('child_process').execSync('echo releasedna-fixture');\n", 'PROCESS_EXECUTION', 'Add inert process-execution text.'),
        ('added-network-indicator', 'network.js', b"fetch('https://example.invalid/releasedna-fixture');\n", 'NETWORK_ACCESS', 'Add inert network text targeting reserved .invalid domain.'),
        ('encoded-eval-indicator', 'encoded.js', b"eval(atob('dm9pZCAw'));\n", 'DYNAMIC_EXECUTION', 'Add inert encoded void-expression text.'),
        ('native-binary-marker', 'helper.bin', b'MZ\x00ReleaseDNA synthetic marker, not a valid executable', 'BINARY_CHANGED', 'Add harmless native-binary signature bytes.')]:
        changed = dict(base)
        changed[path] = File(data)
        add(identity, 'is-number', changed, path, rule, description)
    changed = dict(base)
    changed['fixture-helper.sh'] = File(b'#!/bin/sh\necho releasedna-fixture\n', True)
    add('unexpected-executable', 'is-number', changed, 'fixture-helper.sh', 'EXECUTABLE_ADDED', 'Add executable mode to an inert shell fixture.')
    changed = dict(base)
    manifest = json.loads(changed['package.json'].data)
    manifest.setdefault('dependencies', {})['releasedna-fixture-placeholder'] = '0.0.0'
    changed['package.json'] = File(json.dumps(manifest, indent=2).encode())
    add('dependency-change', 'is-number', changed, 'package.json', 'DEPENDENCIES_CHANGED', 'Add a dependency declaration; do not resolve or install it.')
    changed = dict(base)
    del changed['index.js']
    add('missing-entrypoint', 'is-number', changed, 'index.js', 'MISSING_ENTRYPOINT', 'Remove the declared main file.')
    changed = dict(mapped)
    map_path = 'dist/mitt.js.map'
    sm = json.loads(changed[map_path].data)
    sm['sourcesContent'][0] += '\n// harmless tampered source-map fixture\n'
    changed[map_path] = File(json.dumps(sm).encode())
    add('altered-map-source', 'mitt', changed, map_path, 'SOURCEMAP_SOURCE_MISMATCH', 'Modify embedded source while keeping repository source unchanged.')
    changed = dict(mapped)
    bundle = 'dist/mitt.js'
    changed[bundle] = File(changed[bundle].data + b"\nrequire('child_process'); eval('void 0');\n")
    add('payload-with-genuine-map', 'mitt', changed, bundle, 'PROCESS_EXECUTION', 'Append inert capability indicators while keeping the original matching map unchanged.')
    changed = dict(mapped)
    changed[bundle] = File(changed[bundle].data + b'\nglobalThis.__releasedna_fixture = 1;\n')
    add('quiet-generated-modification', 'mitt', changed, bundle, 'UNEXPLAINED_CODE',
        'Append harmless runtime state change to generated output without capability signatures. Known coverage gap, included in recall denominator.', True)
    return cases


def benign_controls(base):
    result = []
    original = dict(base)
    changed = dict(base)
    changed['package.json'] = File(json.dumps(json.loads(base['package.json'].data), separators=(',', ':')).encode())
    result.append(('manifest-formatting', changed, original))
    changed = dict(base)
    value = json.loads(base['package.json'].data)
    value['_fixture_metadata'] = 'harmless packaging metadata'
    changed['package.json'] = File(json.dumps(value).encode())
    result.append(('registry-metadata', changed, original))
    meta = File(b'{"name":"controlled-build","version":"1.0.0","main":"dist/index.js","files":["dist"],"scripts":{"build":"tsc"}}')
    source = {'package.json': meta, 'src/index.ts': File(b'export const answer: number = 42;\n')}
    sm = File(json.dumps({'version':3,'file':'index.js','sources':['../src/index.ts'],
                         'sourcesContent':['export const answer: number = 42;\n'],'names':[], 'mappings':''}).encode())
    artifact = {'package.json':meta, 'dist/index.js':File(b'export const answer = 42;\n//# sourceMappingURL=index.js.map\n'), 'dist/index.js.map':sm}
    result.append(('controlled-compiled-output', artifact, source))
    return result
