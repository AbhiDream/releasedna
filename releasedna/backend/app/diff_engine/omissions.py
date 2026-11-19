"""Conservative packaging explanations; never run npm or package scripts."""
import json
import posixpath
import re
from pathlib import PurePosixPath

CODE = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py', '.sh', '.ps1', '.bat', '.cmd', '.node', '.wasm'}
DEVELOPMENT = {'.gitignore', '.npmignore', '.gitattributes', '.editorconfig', '.eslintrc',
               '.eslintrc.json', '.travis.yml', '.jshintrc', '.npmrc', 'package-lock.json',
               'yarn.lock', 'pnpm-lock.yaml', 'Makefile', 'Gruntfile.js', 'gulpfile.js'}


def manifest(files):
    try:
        value = json.loads(files['package.json'].data)
        return value if isinstance(value, dict) else {}
    except (KeyError, ValueError, UnicodeError):
        return {}


def strings(value, depth=0):
    if depth > 12:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, dict)):
        for item in (value.values() if isinstance(value, dict) else value):
            yield from strings(item, depth + 1)


def literal_path(value):
    if not isinstance(value, str) or not value or re.search(r'[*!?\[\]{}()\\:]', value):
        return None
    value = value.removeprefix('./').rstrip('/')
    if not value or value.startswith('/') or '..' in value.split('/'):
        return None
    return value


def contains(path, directory):
    return path == directory or path.startswith(directory + '/')


class Omissions:
    def __init__(self, artifact, source):
        self.source = source
        self.artifact = artifact
        self.metadata = manifest(source)
        self.entrypoints = {}
        self.entry_patterns = []
        for origin, meta in [('source', self.metadata), ('artifact', manifest(artifact))]:
            for field in ('main', 'module', 'bin', 'browser', 'exports', 'types', 'typings'):
                for value in strings(meta.get(field)):
                    path = literal_path(value)
                    if path:
                        self.entrypoints[path] = f'{origin}/package.json:{field}'
                    elif isinstance(value, str) and value.startswith('./') and value.count('*') == 1:
                        self.entry_patterns.append((value[2:].split('*'), f'{origin}/package.json:{field}'))
            if meta and not meta.get('main') and 'index.js' in source:
                self.entrypoints['index.js'] = f'{origin}/package.json:default main=index.js'
        self.runtime = {}
        # Static local references from shipped JS are stronger evidence than ignore rules.
        # No dynamic resolution or package code execution is performed.
        for path, item in artifact.items():
            if PurePosixPath(path).suffix not in {'.js', '.cjs', '.mjs', '.ts'}:
                continue
            content = item.data.decode('utf-8', errors='replace')
            pattern = r'''(?:require\s*\(\s*|from\s+|import\s*\(\s*|import\s*)["'](\.[^"']+)["']'''
            for match in re.finditer(pattern, content):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), match.group(1)))
                if target.startswith('../'):
                    continue
                for candidate in (target, target + '.js', target + '.json', target + '.node', target + '/index.js'):
                    if candidate in source:
                        self.runtime[candidate] = f'{path}:{content.count(chr(10), 0, match.start()) + 1} imports {match.group(1)}'
                        break
        declared = self.metadata.get('files')
        self.files = [literal_path(x) for x in declared] if isinstance(declared, list) else None
        # Import here to avoid a module initialization cycle with generated.manifest.
        from app.diff_engine.generated import package_pattern
        self.file_patterns = [package_pattern(x) for x in declared] if isinstance(declared, list) else None
        self.ignore_path = '.npmignore' if '.npmignore' in source else '.gitignore'
        self.ignored = []
        if self.metadata and self.ignore_path in source:
            lines = source[self.ignore_path].data.decode('utf-8', errors='replace').splitlines()
            # Complex/negated patterns need full npm semantics. Abstain instead of misclassifying.
            if all(not line.strip().startswith('!') for line in lines):
                for number, line in enumerate(lines, 1):
                    line = line.strip()
                    if line and not line.startswith('#') and literal_path(line.lstrip('/')):
                        self.ignored.append((line, number))

    def classify(self, path):
        def result(category, classification, rule, explanation, points=0):
            return {'omission_kind': category, 'classification': classification,
                    'omission_rule': rule, 'explanation': explanation, 'points': points}
        reference = self.entrypoints.get(path)
        if not reference:
            reference = next((origin for (prefix, suffix), origin in self.entry_patterns
                              if path.startswith(prefix) and path.endswith(suffix)), None)
        if reference or path == 'package.json':
            return result('package_entrypoint', 'suspicious', 'MISSING_ENTRYPOINT',
                          f'Package entrypoint/manifest absent from artifact; declaration: {reference or path}', 40)
        if path in self.runtime:
            return result('runtime', 'suspicious', 'MISSING_RUNTIME_FILE', self.runtime[path], 30)
        if self.file_patterns is not None and any(x and x.fullmatch(path) for x in self.file_patterns):
            return result('runtime', 'suspicious', 'MISSING_DECLARED_FILE',
                          'Source package.json files explicitly includes this path, but it is absent.', 25)
        parts = PurePosixPath(path).parts
        name = parts[-1]
        if any(p.lower() in {'test', 'tests', '__tests__', 'fixtures', 'bench', 'benchmark', 'benchmarks'} for p in parts) or re.search(r'(?:^test\.|\.(?:test|spec)\.)', name):
            return result('tests', 'expected', 'OMITTED_TEST', 'Test/benchmark convention; no detected shipped-code reference or declared inclusion.')
        if any(p.lower() in {'docs', 'doc', 'examples'} for p in parts) or name.lower().endswith(('.md', '.rst')):
            return result('documentation', 'expected', 'OMITTED_DOCUMENTATION', 'Documentation/example convention; no detected runtime reference or declared inclusion.')
        if path in DEVELOPMENT or parts[0] in {'.github', '.git', '.circleci'}:
            return result('development', 'expected', 'OMITTED_DEVELOPMENT', 'Development/CI configuration normally omitted from publishing.')
        # Fully understood literal files lists can explain omitted build inputs, but not entrypoints/references.
        if self.file_patterns is not None and all(self.file_patterns):
            return result('packaging_exclusion', 'expected', 'NPM_FILES_EXCLUSION',
                          'Outside the supported source package.json files allowlist; no detected runtime reference. Supported patterns: literals, *, ** and ?.')
        for pattern, line in self.ignored:
            normalized = pattern.lstrip('/').rstrip('/')
            matched = contains(path, normalized) if '/' in normalized or pattern.startswith('/') else normalized in parts
            if matched:
                return result('packaging_exclusion', 'expected', 'NPM_IGNORE_EXCLUSION',
                              f'{self.ignore_path}:{line} explicitly excludes {pattern!r}; no detected runtime reference.')
        if PurePosixPath(path).suffix in CODE or parts[0] in {'lib', 'runtime', 'dist'}:
            return result('runtime', 'suspicious', 'MISSING_RUNTIME_FILE',
                          'Potential runtime/build code is absent without a supported packaging explanation.', 20)
        return result('unexplained', 'unexplained', 'UNEXPLAINED_OMISSION',
                      'No runtime declaration or supported packaging rule explains this missing file.')
