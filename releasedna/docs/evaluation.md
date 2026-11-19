# Detector evaluation and judge demonstration

This milestone adds an executable evaluation harness, not fabricated demo verdicts. It captures official public releases, verifies registry digests, resolves source revisions, and replays the exact production archive inspector and comparator. Harmless mutated archives use that same pipeline. No package is installed, imported, executed or built.

## Run it

From `releasedna/backend`, with the existing virtual environment:

```powershell
# Network capture: downloads fixed versions and source archives as data.
..\.venv\Scripts\python -m app.evaluation capture

# Reproducible offline replay, including every mutation and benign control.
..\.venv\Scripts\python -m app.evaluation run --include-fixtures

# Regressions (no network, no fetched package execution).
..\.venv\Scripts\python -m unittest discover -s tests -v
```

The capture command stores bounded archives plus provenance in `data/evaluation-cache`. Replay verifies cache SHA256 hashes and the captured official registry artifact digest. Invalid cache data fails rather than being silently accepted. Missing capture data must be fetched first. All current source archives are tar.gz; the normal inspector also supports ZIP. No fixture findings are stored as expected scanner output in the implementation.

Reports are generated as `data/evaluation.json`, `.md`, and `.html`. With the backend running, open http://127.0.0.1:8000/evaluation. The scan console links to this report; `/api/evaluation` downloads the full JSON. The evaluation page is read-only and displays the last executed evaluation, not a fresh scan on every page visit.

## Demonstration sequence

1. Open the real scan console and scan `npm / is-number / 7.0.0` for the baseline.
2. Open Detector evaluation. Expand **added-install-hook**: inspect `INSTALL_SCRIPT_CHANGED`, `package.json`, the exact added postinstall command, line evidence and unified diff.
3. Expand **payload-with-genuine-map**: the unchanged source map still matches the repository, but the appended process/dynamic-execution indicators are detected. A map cannot whitelist a bundle.
4. Expand public **mitt@3.0.1**: inspect build declarations, normalized `../src/index.ts` mapping, matching embedded source and `generated_unverified` output. It has no suspicious findings but remains INCONCLUSIVE because a build was not reproduced.
5. Show **quiet-generated-modification** and the held-out public alerts. These are known shortcomings, not hidden successes. The report keeps misses and uncertainty visible.

## What changed

The old comparator flagged any code absent from source as suspicious. The new comparator recognizes output declared by repository package metadata and a build script. It attaches the declaration, source-map matches/mismatches and an explicit equivalence-unverified flag. Strong indicator rules still inspect generated outputs. Merely placing a file under `dist/` does not exempt it.

Source-map inspection validates a bounded version-3 structure, resolves relative references only within the in-memory repository namespace, compares every available embedded source byte-for-byte, and rejects URLs/traversal as unresolved. It never downloads map references. Missing sourcesContent, unsupported structures and mismatches are not called verified. Mappings themselves are not validated; no emitted-code equivalence is inferred.

The npm files adapter now supports a restricted subset of `*`, `**`, and `?` patterns as well as literal paths. Negative patterns, braces/extglobs, root-leading slash forms and nested ignore interactions are not fully supported. Unsupported forms stay conservative; this is one source of remaining false alerts.

## Evaluation design and results

The corpus was fixed before detector changes: four development releases and four holdout releases. Development findings informed generic changes. Detector commit `f88adf8` was recorded before fetching and evaluating the holdout set. No detector tuning was performed after seeing those holdout findings. The output records both the corpus and detector SHA256.

Measured results on this run:

- Harmless tampering: **11/12 detected (91.7%)**, requiring a new finding with the predeclared rule at the exact modified path.
- Presumed-benign public releases: **3/8 alerted (37.5%)**. This is a false-positive proxy, not certified ground truth.
- Public results: **2 CLEAN, 6 INCONCLUSIVE**, including three inconclusive releases that also have suspicious findings. Abstentions are not counted as correct clean results.
- Development public alerts fell from **2/4 before to 0/4 after**; holdout alerts were **3/4**. The development reduction does not establish good out-of-sample specificity.
- Controlled benign transformations: **0/3 alerted**.
- **58 unit/regression tests passed**. No public retrieval failures occurred in this run.

Final verification: two offline replays produced identical JSON after excluding the generation timestamp. A fresh real API scan of `mitt@3.0.1` completed INCONCLUSIVE with zero findings. Both evaluation HTTP routes returned 200 and the downloaded JSON matched the saved report. Frontend JavaScript syntax checks passed, and the evaluation page and installation-hook evidence were inspected in the browser. The test suite uses unittest; pytest is not installed in this environment.

The false-positive goal is only partially met. `clsx` and `mitt` generated outputs are explained without suspicious findings, but held-out `nanoid`, `tiny-invariant` and PyPI `packaging` still generate review findings. Do not claim low ecosystem-wide false-positive rates from this benchmark.

## Specific remaining gaps

- **nanoid@5.1.5:** comment/blank-line removal and build-tool configuration omissions trigger generic code-difference/runtime rules. The CLI also changes blank lines inside a help template string, so blindly stripping whitespace would conceal a real string change.
- **tiny-invariant@1.3.3:** root-leading slash forms in its npm files list are unsupported; some output declarations and build configuration omissions are therefore unexplained.
- **packaging==25.0:** development `noxfile.py` and `tasks/*.py` are flagged as missing runtime files; Python packaging/development dependency relationships need a stronger adapter.
- **quiet-generated-modification:** a harmless appended global assignment has no capability signature and is missed. The report remains INCONCLUSIVE. Detecting arbitrary semantic changes to compiled output needs stronger transformation verification or trusted reproducible-build evidence.

No live malware was used. Mutations are inert text/metadata/binary markers; any network-looking text uses a reserved `.invalid` domain. Fixture digests are labeled local and **not** registry-verified. The real baseline's registry digest is retained separately.

This is a small, historical convenience sample, not an independent malware benchmark. The percentages describe these cases only. The full generated result is saved in [evaluation-results.md](evaluation-results.md), with machine-readable evidence in [evaluation-results.json](evaluation-results.json). The initial development baseline is preserved in [evaluation-before-development.json](evaluation-before-development.json).

Reference for source-map fields and relative resolution: [ECMA-426](https://tc39.es/ecma426/2024/). Source maps are debugging metadata, not build provenance attestations.
