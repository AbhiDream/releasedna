# Contributor corpus: measured AI-assisted evaluation

This contribution adds twelve synthetic comparisons without changing the detector. Despite the historical filename, this is **AI-assisted, known-rule development evaluation**, not independent blind validation, organizer testing or a public-release sample. A contributor should review and replay it before submitting their PR; no result here is attributed to Kirti or Sanskriti.

## Protocol

Complete input bytes, executable flags, labels and exact expected rule/path outcomes were committed before the first detector run in commit `8d114b5` (`test: preregister AI-assisted contributor corpus and exact input hashes`). The frozen detector is main commit `3a93ae3d5b0cd7ee6fe51f5f248ac1981d142a80`, fingerprint `593bf2033947f0d0cbdb26c0fd99229643586c27a058d16df19b019f14e827ad`. Expectations were designed with knowledge of the rules, so preregistration alone does not make this an unseen holdout.

Each case carries canonical input hashes. The harness validates IDs, labels, expected paths, limits and all three snapshots before comparison. It serializes them to deterministic tar/gzip archives, reads them through the production non-extracting inspector, and compares both baseline and mutated artifacts against controlled source. Fixture text is never imported, installed, built or executed. Synthetic inputs have no official package identity, real publication date or registry-integrity claim.

Controlled source identity is passed to the comparator only to test the file-difference layer. This is distinct from an actual local upload, whose report retains unverified user-supplied source identity.

## First measured run — 19 November 2026

Environment: Windows, Python 3.13.1. Results are preserved in [complete JSON evidence](contributor-evaluation.json) and [the generated table](contributor-evaluation-results.md).

| Measure | Result |
| --- | --- |
| Cases inspected / errors | 12 / 0 |
| Tampered TP / FN | 5 / 1 |
| Tampered detection rate | 5/6 = 83.3% |
| Benign FP / TN | 2 / 4 |
| Benign false-positive rate | 2/6 = 33.3% |
| INCONCLUSIVE comparisons | 2/12 |

TP requires a new finding with the preregistered rule **and exact path**, absent from the unmodified baseline. An unrelated alert is not a TP. Removed-file findings use source_path where artifact_path is absent. Errors are separately retained, never counted as correct classifications. Empty denominators produce null/not measured. Abstention is reported separately and is not CLEAN.

## What the cases establish

- Detected: missing exported npm subpath; added configure macro; missing statically imported Python module; process indicator in configuration; decoder indicator in a data file.
- Miss retained: a quiet generated constant changed **before** the source-map trailer while matching embedded source remained unchanged. The comparator abstained but did not emit the expected tampering finding. This is an FN, not a successful detection.
- False alarms retained: benign wheel metadata and a generated Python version file lacked a validated packaging explanation. These are counted as FP for the controlled labels.
- No alerts: syntax-preserving JS/Python comments/layout, an existing regex exec expression reformatted, and declared compiled output with map/declaration context. The compiled-output case still remains INCONCLUSIVE because equivalence is unverified.

No detector rules were changed or exceptions added after seeing these outcomes. This corpus is small, synthetic and intentionally includes challenging cases; its percentages do not estimate ecosystem-wide accuracy.

## Reproduce

Use Python 3.11+ and install the application's pinned requirements from the `releasedna` folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
Set-Location backend
..\.venv\Scripts\python.exe -m app.contributor_evaluation --output ..\data\contributor-evaluation.json
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The harness needs no network, downloaded package execution or AI key. It rejects a changed detector fingerprint instead of silently overwriting this experiment with incomparable results. Future detector versions need a separate explicitly registered experiment. Replay changes the timestamp/environment fields; case evidence and metrics should remain identical on the pinned parser/runtime dependencies.

Five new harness tests verify accounting, exact-path/baseline matching, schema/input-tampering rejection, repeatability, frozen-detector rejection and analysis-error handling. **91 total backend tests passed** in the final run (4.442 seconds). These tests verify harness behavior; they do not turn the one missed fixture or two false alarms into passing detections.

## Contributor handoff

Review the manifest and implementation, run the commands yourself and append your environment and observed outcomes in the PR description. Identify which parts were AI-prepared and what you personally reviewed or changed. Do not claim authorship of an independent blind corpus or claim that you ran the recorded maintainer-side tests. Organizer samples and fresh real-release evaluation remain separate future work.
