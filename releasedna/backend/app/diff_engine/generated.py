"""Explain build output using repository evidence, without building or trusting maps."""
import json
import posixpath
import re
from pathlib import PurePosixPath
from app.diff_engine.omissions import manifest, strings


def package_pattern(pattern):
    """Supported npm-files subset: literals, *, ** and ?. No negation/extglobs."""
    if not isinstance(pattern, str) or not pattern or re.search(r'[!\[\]{}()\\:]', pattern):
        return None
    pattern = pattern.removeprefix('./').rstrip('/')
    if pattern.startswith('/') or '..' in pattern.split('/'):
        return None
    escaped = re.escape(pattern)
    escaped = escaped.replace(r'\*\*/', '(?:.*/)?').replace(r'\*\*', '.*').replace(r'\*', '[^/]*').replace(r'\?', '[^/]')
    return re.compile(r'^' + escaped + r'(?:/.*)?$')


def local_reference(base, value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        return None
    if value.startswith('/') or re.search(r'[:\\?#\x00-\x1f]', value):
        return None
    path = posixpath.normpath(posixpath.join(base, value))
    return None if path in ('.', '..') or path.startswith('../') else path


def map_evidence(path, data, source):
    evidence = {'map_path': path, 'matching_sources': [], 'mismatched_sources': [],
                'unresolved_sources': [], 'all_embedded_sources_match': False, 'valid_structure': False}
    try:
        sm = json.loads(data)
        if not isinstance(sm, dict) or sm.get('version') != 3:
            raise ValueError('Expected a version 3 source map')
        origins, contents = sm.get('sources'), sm.get('sourcesContent')
        root = sm.get('sourceRoot') or ''
        if (not isinstance(origins, list) or not origins or len(origins) > 1000
                or not isinstance(contents, list) or len(origins) != len(contents)
                or not isinstance(root, str) or not isinstance(sm.get('mappings'), str)):
            raise ValueError('Missing, unsupported or oversized source-map structure')
        evidence['valid_structure'] = True
        for index, (origin, content) in enumerate(zip(origins, contents)):
            target = local_reference(posixpath.dirname(path), root.rstrip('/') + '/' + origin if root and isinstance(origin, str) else origin)
            item = {'source_index': index, 'declared_path': origin, 'source_path': target}
            if target is None or target not in source or not isinstance(content, str):
                evidence['unresolved_sources'].append(item)
            elif content.encode('utf-8') == source[target].data:
                evidence['matching_sources'].append(item)
            else:
                item['source_sha256'] = source[target].sha256
                import hashlib
                item['embedded_sha256'] = hashlib.sha256(content.encode('utf-8')).hexdigest()
                evidence['mismatched_sources'].append(item)
        evidence['all_embedded_sources_match'] = bool(evidence['matching_sources']) and not evidence['mismatched_sources'] and not evidence['unresolved_sources']
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        evidence['error'] = str(exc)
    evidence['limitation'] = 'Embedded-source matching does not validate mappings or prove the generated bundle is equivalent to source.'
    return evidence


class GeneratedContext:
    def __init__(self, artifact, source):
        self.artifact, self.source = artifact, source
        self.maps = {p: map_evidence(p, f.data, source) for p, f in artifact.items() if p.endswith('.map')}
        self.metadata = manifest(source)
        scripts = self.metadata.get('scripts', {})
        self.build = {key: value for key, value in scripts.items() if key in ('build', 'bundle', 'compile', 'prepack') and isinstance(value, str)} if isinstance(scripts, dict) else {}
        self.targets = {}
        for field in ('main', 'module', 'exports', 'types', 'typings', 'unpkg', 'jsnext:main', 'umd:main', 'browser'):
            for target in strings(self.metadata.get(field)):
                path = local_reference('', target)
                if path:
                    self.targets[path] = 'package.json:' + field
        declared = self.metadata.get('files')
        self.patterns = [(p, package_pattern(p)) for p in declared] if isinstance(declared, list) else []

    def explain(self, path):
        if path in self.source or not self.build:
            return None
        target = self.targets.get(path)
        matches = [p for p, regex in self.patterns if regex and regex.fullmatch(path)]
        if not target and not matches:
            return None
        if PurePosixPath(path).suffix not in {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'}:
            return None
        evidence = {'manifest_path': 'package.json', 'build_scripts': self.build,
                    'output_declaration': target or 'package.json:files', 'matching_files_patterns': matches,
                    'equivalence_verified': False}
        content = self.artifact[path].data.decode('utf-8', errors='replace')
        links = re.findall(r'(?m)^\s*//[#@]\s*sourceMappingURL=([^\s]+)\s*$', content)
        if links:
            map_path = local_reference(posixpath.dirname(path), links[-1])
            if map_path in self.maps:
                evidence['source_map'] = self.maps[map_path]
        evidence['explanation'] = ('Declared build output: repository package.json declares a build and this output path. '
                                   'Its absence from the repository is expected for a build, but emitted-code equivalence is unverified. '
                                   'Capability and tampering rules still apply.')
        return evidence
