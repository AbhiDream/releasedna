import json
import unittest
from app.core.safety import File, inspect_archive
from app.diff_engine.compare import compare
from app.diff_engine.generated import map_evidence, package_pattern
from app.evaluation_fixtures import pack


class GeneratedTests(unittest.TestCase):
    def setUp(self):
        self.meta = File(b'{"main":"dist/a.js","files":["dist","*.d.ts"],"scripts":{"build":"tsc"}}')
        self.source = {'package.json':self.meta, 'src/a.ts':File(b'export const answer: number = 42;')}
        self.sm = {'version':3,'sources':['../src/a.ts'],'sourcesContent':['export const answer: number = 42;'], 'mappings':''}
        self.artifact = {'package.json':self.meta, 'dist/a.js':File(b'export const answer = 42;\n//# sourceMappingURL=a.js.map\n'), 'dist/a.js.map':File(json.dumps(self.sm).encode())}

    def test_compiled_output_no_alarm_but_not_clean(self):
        result = compare(self.artifact, self.source, True)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        row = next(r for r in result['files'] if r['path']=='dist/a.js')
        self.assertEqual(row['classification'], 'generated_unverified')
        self.assertTrue(row['build_evidence']['source_map']['all_embedded_sources_match'])
        self.assertFalse(row['build_evidence']['equivalence_verified'])

    def test_matching_map_cannot_hide_payload(self):
        self.artifact['dist/a.js'] = File(self.artifact['dist/a.js'].data + b"\nrequire('child_process'); eval('void 0');")
        result = compare(self.artifact, self.source, True)
        self.assertIn('PROCESS_EXECUTION', result['risk_reasons'])
        self.assertIn('DYNAMIC_EXECUTION', result['risk_reasons'])

    def test_forged_mismatched_embedded_source(self):
        self.sm['sourcesContent'] = ['export const answer: number = 99;']
        self.artifact['dist/a.js.map'] = File(json.dumps(self.sm).encode())
        result = compare(self.artifact, self.source, True)
        self.assertIn('SOURCEMAP_SOURCE_MISMATCH', result['risk_reasons'])
        evidence = next(f for f in result['findings'] if f['rule']=='SOURCEMAP_SOURCE_MISMATCH')['evidence'][0]
        self.assertEqual(evidence['source_path'], 'src/a.ts')
        self.assertNotEqual(evidence['embedded_sha256'], evidence['source_sha256'])

    def test_absent_build_declaration_not_automatically_trusted(self):
        self.source['package.json'] = File(b'{"main":"dist/a.js"}')
        self.assertIn('UNEXPLAINED_CODE', compare(self.artifact, self.source, True)['risk_reasons'])

    def test_map_path_traversal_and_remote_reference_never_resolved(self):
        for path in ['../../../outside.ts', 'https://example.invalid/a.ts', 'C:\\a.ts']:
            self.sm['sources'] = [path]
            result = map_evidence('dist/a.js.map', json.dumps(self.sm).encode(), self.source)
            self.assertFalse(result['all_embedded_sources_match'])
            self.assertEqual(len(result['unresolved_sources']), 1)

    def test_truncated_contents_and_wrong_version_not_trusted(self):
        for change in [{'sourcesContent':[]}, {'version':2}, {'sources':'src/a.ts'}, {'mappings':None}]:
            result = map_evidence('dist/a.js.map', json.dumps({**self.sm, **change}).encode(), self.source)
            self.assertFalse(result['all_embedded_sources_match'])

    def test_same_path_modified_source_not_treated_as_generated(self):
        self.source['dist/a.js'] = File(b'export const answer = 41;')
        result = compare(self.artifact, self.source, True)
        self.assertIn('UNEXPLAINED_CODE', result['risk_reasons'])

    def test_supported_globs_and_unsupported_negations(self):
        self.assertTrue(package_pattern('*.d.ts').fullmatch('index.d.ts'))
        self.assertFalse(package_pattern('*.d.ts').fullmatch('src/index.d.ts'))
        self.assertTrue(package_pattern('src/**/*.js').fullmatch('src/a.js'))
        self.assertTrue(package_pattern('src/**/*.js').fullmatch('src/nested/a.js'))
        self.assertIsNone(package_pattern('!private'))
        self.assertIsNone(package_pattern('{src,lib}'))

    def test_fixture_archive_roundtrip_deterministic(self):
        data = {'a.js':File(b'void 0;',True)}
        self.assertEqual(pack(data), pack(data))
        self.assertEqual(inspect_archive(pack(data)), data)

    def test_documented_quiet_bundle_gap_remains_inconclusive(self):
        self.artifact['dist/a.js'] = File(self.artifact['dist/a.js'].data + b'\nglobalThis.fixture = 1;')
        report = compare(self.artifact, self.source, True)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
