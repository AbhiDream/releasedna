# Recovering a reproducible corpus after the main integration

On 20 November 2026, main advanced to `f9bc28d` with PRs #4 and #5 while the remote deployment branch was in progress. Merging main exposed an actual regression: the contributor evaluation test failed because `backend/evaluation/contributor-corpus.json` contained the generated report instead of the fixture inputs. The report lacks `source_files` and `artifact_files`; it cannot reproduce its own experiment.

The report references contributor commit `36df57d579e6c8438afd533d1a9d18526ea17a33`. Reading that exact commit showed a one-byte, whitespace-only manifest. Therefore the contributor experiment's original inputs cannot be recovered from that preregistration file. This is an observed file/provenance issue, not an allegation about its cause or about the contributor's intent.

To unblock the Docker build without disabling the failing tests or inventing missing inputs, the following three files were restored from the previously prepared complete implementation at `5c4bf6f10f1da277674c41131f5a8613e9e68adb`:

- `backend/evaluation/contributor-corpus.json`
- `backend/app/contributor_evaluation.py`
- `backend/tests/test_contributor_evaluation.py`

This is a **different, explicitly identified AI-assisted maintainer experiment**. Its complete source/baseline/artifact bytes and expected rule/path outcomes were committed in `8d114b5` before its first run. Its harness pins the detector fingerprint, verifies input hashes and requires a new expected rule at the exact path beyond baseline findings. It is not independent blind validation and is not attributed to Kirti's personal execution.

The previously submitted `docs/contributor-evaluation.json` remains untouched as a historical contributor-submitted report. Its reproducibility is **unverified** without the original input manifest. Do not pair that historical file's manifest hash or environment with this restored experiment. The historical documentation has a notice linking here.

The prepared maintainer experiment's actual first-run evidence is separately preserved as [JSON](maintainer-recovery-evaluation.json) and [table](maintainer-recovery-evaluation.md): TP5/FN1, FP2/TN4, 0 errors and 2 inconclusive comparisons. A fresh replay on 20 November confirmed the same counts. No detector scores, labels or expected outcomes were tuned during recovery.

Reproduce from `releasedna/backend`:

```powershell
..\.venv\Scripts\python.exe -m app.contributor_evaluation --output ..\data\maintainer-recovery-replay.json
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The old contributor harness API (`run_evaluation`, `--corpus`) has been replaced by the prepared `run`/`--manifest` interface; existing no-argument and `--output` module usage remains supported. The historical contributor report and Git authorship/PR history are retained. This recovery is part of the maintainer deployment PR, not a new PR impersonating a contributor.
