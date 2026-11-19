"""Offline, harmless structural analogues. Not an actual xz/debug exploit corpus."""
import hashlib
import json
from pathlib import Path
from html import escape
from app.core.safety import File, inspect_archive
from app.diff_engine.compare import compare
from app.diff_engine.fingerprint import detector_fingerprint
from app.evaluation_fixtures import pack

ROOT = Path(__file__).resolve().parents[2]


def cases():
    source = {'package.json':File(b'{"name":"fixture","version":"1.0.0","main":"index.js"}'),
              'index.js':File(b'module.exports = 1;\n'),
              'm4/build.m4':File(b'dnl harmless build macro\n'),
              'tests/data.bin':File(b'harmless test data\n')}
    rows = []
    def add(name, family, path, data, rule, tampered=True):
        artifact = dict(source)
        artifact[path] = File(data)
        rows.append(dict(id=name,family=family,target=path,expected_rule=rule,tampered=tampered,artifact=artifact,source=source))
    noise = b''.join(hashlib.sha256(str(i).encode()).digest() for i in range(128))
    for path in ('m4/build.m4', 'm4/release-only.m4', 'build/setup.sh', 'tests/disguised.dat'):
        add('xz-script-'+path.replace('/','-'), 'xz-style', path,
            b'# inert fixture: never execute\nm4_esyscmd([printf fixture])\n', 'SHELL_PIPELINE')
    for path in ('tests/data.bin','tests/release-only.blob'):
        add('xz-entropy-'+path.replace('/','-'), 'xz-style', path, noise, 'HIGH_ENTROPY_CHANGE')
    add('xz-low-entropy-blob','xz-style','tests/data.bin',b'changed opaque content\x00', 'UNEXPLAINED_NONCODE')
    for path in ('index.js','debug/helper.js','debug/notes.txt'):
        add('debug-process-'+path.replace('/','-'), 'debug-style', path,
            b"// inert text only\nrequire('child_process').execSync('echo fixture');\n", 'PROCESS_EXECUTION')
    add('debug-hook','debug-style','package.json',b'{"name":"fixture","version":"1.0.0","main":"index.js","scripts":{"postinstall":"node -e \\\"void 0\\\""}}', 'INSTALL_SCRIPT_CHANGED')
    # Known benign changed blobs/docs are deliberately included to expose heuristic false alarms.
    add('benign-release-note','control','CHANGELOG.md',b'Release notes for this version.\n',None,False)
    add('benign-compressed-data','control','assets/sample.bin',noise,None,False)
    add('benign-regexp-exec','control','index.js',b'const match = /ok/.exec("ok");\n',None,False)
    rows.append(dict(id='unchanged-build-macro',family='control',target='m4/build.m4',expected_rule=None,tampered=False,artifact=source,source=source))
    return rows


def run(output=None):
    output = Path(output or ROOT/'data/adversarial.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    # Reusable local-input demo archives. These are data-only synthetic fixtures.
    for label,family in [('xz','xz-style'),('debug','debug-style')]:
        demo=next(case for case in cases() if case['family']==family)
        for side in ('artifact','source'):
            (output.parent/f'demo-{label}-{side}.tgz').write_bytes(pack(demo[side]))
    rows=[]
    for case in cases():
        blob=pack(case['artifact'])
        report=compare(inspect_archive(blob),inspect_archive(pack(case['source'])),True)
        matched=[f for f in report['findings'] if f['rule']==case['expected_rule'] and f['artifact_path']==case['target']]
        rows.append({k:v for k,v in case.items() if k not in ('artifact','source')} | {'artifact_sha256':hashlib.sha256(blob).hexdigest(),'detected':bool(matched),'alerted':bool(report['findings']),'report':report})
    table=[]
    for family in ('xz-style','debug-style','all'):
        positives=[r for r in rows if r['tampered'] and (family=='all' or r['family']==family)]
        negatives=[r for r in rows if not r['tampered']]
        tp=sum(r['detected'] for r in positives); fp=sum(r['alerted'] for r in negatives)
        table.append(dict(family=family,TP=tp,FN=len(positives)-tp,FP=fp,TN=len(negatives)-fp,TPR=tp/len(positives),FPR=fp/len(negatives)))
    result={'engine_version':'0.2.0','detector_sha256':detector_fingerprint(),'detector_hash_format':'sha256-named-files-lf-v1',
            'artifact_integrity':'Local synthetic fixture digests; not verified official registry artifacts.',
            'scope':'Synthetic structural analogues, not historical exploit detection. No fixture code executed. Shared controls for each family. Exact expected rule and path required for TP.', 'table':table,'cases':rows}
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    html='<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ReleaseDNA structural tampering corpus</title><style>body{font:16px system-ui;background:#101827;color:#eee;max-width:1100px;margin:30px auto;padding:20px}a{color:#80e6cf}td,th{padding:12px;border:1px solid #456}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{padding:16px;border:1px solid #456;margin:12px 0}.badge{display:inline-block;margin-top:12px;background:#fffff0;color:#473b21;border-radius:20px;padding:6px 12px}</style><a href="/">Scan console</a><h1>Build-file tampering, made visible</h1><p>'+escape(result['scope'])+'</p><table><tr><th>Family</th><th>TP</th><th>FN</th><th>FP</th><th>TN</th><th>TPR</th><th>FPR</th></tr>'
    for r in table:
        html+='<tr>'+''.join('<td>'+escape(str(r[k]) if k not in ('TPR','FPR') else f'{r[k]:.1%}')+'</td>' for k in ('family','TP','FN','FP','TN','TPR','FPR'))+'</tr>'
    html+='</table><p>False alarms are retained. High entropy and unexplained differences do not prove malicious intent.</p>'
    for r in rows:
        html+='<details><summary>'+escape(r['id'])+(' · anomaly spotted' if r['alerted'] else ' · no alert')+'</summary><span class="badge">'+('Anomaly spotted' if r['alerted'] else 'No anomaly reported')+'</span><p>Local synthetic fixture · risk score '+str(r['report']['risk_score'])+'</p>'
        for finding in r['report']['findings']:
            html+='<h3>'+escape(finding['rule']+' · '+str(finding['artifact_path']))+'</h3><p>'+escape(finding['message'])+'</p><pre>'+escape(json.dumps(finding['evidence'],indent=2))+'</pre><pre>'+escape(finding['diff'])+'</pre>'
        html+='<details><summary>Full fixture evidence</summary><pre>'+escape(json.dumps(r,indent=2))+'</pre></details></details>'
    output.with_suffix('.html').write_text(html,encoding='utf-8')
    print(json.dumps(table,indent=2))
    return result


if __name__=='__main__':
    run()
