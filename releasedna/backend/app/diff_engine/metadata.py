"""Narrow, data-only packaging explanations. Never exempt a directory by name."""
import hashlib
import json
import posixpath
from pathlib import PurePosixPath
from app.diff_engine.omissions import strings

# Whitespace-normalized hashes of pytest's published cache-support templates.
# https://github.com/pytest-dev/pytest/blob/main/src/_pytest/cacheprovider.py
PYTEST_TEMPLATES = {
    '.gitignore':'b01b8030779cb837dd759183e03eae3a51a0b652c061f654a50af53e9bcbbb98',
    'CACHEDIR.TAG':'157e48c61da49a2ad44fbfa3f8f06e678d88259be2be1274ec6152c3bd3320bd',
    'README.md':'7257f113e50bcc33fa18e9b52680bfde8d200b240a4bcfb3eeedfcb2bec9429e',
}


def explain_metadata(path, data, generated):
    parts=PurePosixPath(path).parts
    if '.pytest_cache' in parts:
        relative='/'.join(parts[parts.index('.pytest_cache')+1:])
        if relative in PYTEST_TEMPLATES and hashlib.sha256(b' '.join(data.split())).hexdigest()==PYTEST_TEMPLATES[relative]:
            return 'Standard pytest cache-support template content matches; not an exemption for other files in this directory.'
        if relative in {'v/cache/nodeids','v/cache/lastfailed','v/cache/stepwise'}:
            try:
                value=json.loads(data)
                valid_id=lambda x:isinstance(x,str) and len(x)<=4096 and '.py::' in x and '\x00' not in x
                valid=(isinstance(value,list) and all(valid_id(x) for x in value)) if relative.endswith('nodeids') else (
                    isinstance(value,dict) and all(valid_id(k) and isinstance(v,bool) for k,v in value.items()) if relative.endswith('lastfailed') else value in ([],None))
                if valid:return 'Recognized pytest test-cache JSON shape. Data is not executed; capability/entropy checks still apply.'
            except (ValueError,UnicodeError,TypeError,RecursionError): pass
    if path.endswith('/package.json'):
        try:
            value=json.loads(data)
            parent=posixpath.dirname(path)+'/'
            module_targets=list(strings(generated.metadata.get('module')))
            def imports(value,depth=0):
                if depth>12 or not isinstance(value,dict):return
                for key,child in value.items():
                    if key=='import': module_targets.extend(strings(child))
                    else: imports(child,depth+1)
            imports(generated.metadata.get('exports'))
            if (value=={'type':'module'} and generated.build
                    and any(target.removeprefix('./').startswith(parent) for target in module_targets)):
                return 'Minimal ESM scope marker for a module output explicitly declared by repository package.json; no scripts or other keys.'
        except (ValueError,UnicodeError,TypeError,RecursionError): pass
    return None
