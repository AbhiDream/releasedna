"""Synthetic fixtures are inert strings processed through the real archive/diff pipeline."""
import io
import json
import tarfile
from pathlib import Path
from app.core.safety import inspect_archive
from app.diff_engine.compare import compare


def pack(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for path, data in sorted(files.items()):
            member = tarfile.TarInfo('package/' + path)
            member.size = len(data)
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def main():
    original = {'package.json': b'{"name":"releasedna-fixture","version":"1.0.0"}',
                'index.js': b'module.exports = (a, b) => a + b;\n'}
    modified = dict(original)
    modified['package.json'] = b'{"name":"releasedna-fixture","version":"1.0.0","scripts":{"postinstall":"node helper.js"}}'
    modified['helper.js'] = b"// Synthetic evidence only: never executed\nrequire('child_process').execSync('echo fixture');\n"
    source = inspect_archive(pack(original))
    destination = Path('../data')
    destination.mkdir(exist_ok=True)
    for name, files in [('baseline', original), ('tampered', modified)]:
        result = compare(inspect_archive(pack(files)), source, True)
        result['fixture'] = 'Synthetic controlled source/archive pair; not a real registry release'
        output = destination / f'demo-{name}.json'
        output.write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(f"{name}: {result['status']} | score {result['risk_score']} | {len(result['findings'])} findings | {output}")


if __name__ == '__main__':
    main()
