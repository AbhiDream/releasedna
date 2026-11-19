# Historical report notice — 20 November 2026

The contributor-submitted report below is retained as history, but its exact original inputs are unavailable in the referenced preregistration commit. The merged input file contained report output and failed validation. The runnable default has been restored to the separately identified prepared maintainer experiment; see [corpus recovery and evidence](contributor-corpus-recovery.md). Do not treat the historical provenance or personal-execution claims below as independently verified by this recovery.

---

# ReleaseDNA Independent Contributor Evaluation

- **Generated at:** 2026-11-19T15:00:57.678576+00:00
- **Preregistration commit:** https://github.com/kirtisihag-1808/releasedna/commit/36df57d579e6c8438afd533d1a9d18526ea17a33
- **Manifest SHA-256:** `d25bba48866c7a787174b361b0c9f1dc6c94f933714cb127dbee81f3591babb5`
- **Detector fingerprint:** `593bf2033947f0d0cbdb26c0fd99229643586c27a058d16df19b019f14e827ad`
- **Environment:** Windows-11-10.0.26300-SP0 | Python 3.15.1
- **AI assistance:** Manifest and harness drafted with Gemini AI assistance; executed and verified by contributor kirtisihag-1808.

## Summary Metrics

| Metric | Result |
| --- | --- |
| Tampered cases inspected | 6 |
| Benign cases inspected | 6 |
| TP / FN / FP / TN | 5 / 1 / 2 / 4 |
| True Positive Rate (TPR) | 5/6 (83.3%) |
| False Positive Rate (FPR) | 2/6 (33.3%) |
| Retrieval / inspection errors | 0 |
| INCONCLUSIVE verdicts | 1 |

## Per-Case Results

| Case ID | Ecosystem | Ground Truth | Expected | Verdict | Outcome |
| --- | --- | --- | --- | --- | --- |
| `npm-tamper-makefile-shell` | npm | harmless tampered fixture | `SHELL_PIPELINE` at `Makefile` | REVIEW | FN (Missed) |
| `npm-tamper-generated-network` | npm | harmless tampered fixture | `NETWORK_ACCESS` at `dist/bundle.min.js` | REVIEW | TP (Detected) |
| `npm-tamper-dynamic-eval` | npm | harmless tampered fixture | `DYNAMIC_EXECUTION` at `src/format.js` | REVIEW | TP (Detected) |
| `pypi-tamper-setup-process` | pypi | harmless tampered fixture | `PROCESS_EXECUTION` at `setup.py` | REVIEW | TP (Detected) |
| `pypi-tamper-generated-network` | pypi | harmless tampered fixture | `NETWORK_ACCESS` at `synthetic_pypi_codegen/_generated_tables.py` | REVIEW | TP (Detected) |
| `pypi-tamper-missing-init` | pypi | harmless tampered fixture | `UNEXPLAINED_CODE` at `synthetic_pypi_lib/helper.py` | REVIEW | TP (Detected) |
| `npm-benign-readme-update` | npm | benign control | No findings | CLEAN | TN (Clean) |
| `npm-benign-clean-build-output` | npm | benign control | No findings | INCONCLUSIVE | TN (Clean) |
| `npm-benign-makefile-comment` | npm | benign control | No findings | REVIEW | FP (False Alarm) |
| `pypi-benign-identical-sdist` | pypi | benign control | No findings | CLEAN | TN (Clean) |
| `pypi-benign-pkg-info-metadata` | pypi | benign control | No findings | CLEAN | TN (Clean) |
| `pypi-benign-docstring-change` | pypi | benign control | No findings | REVIEW | FP (False Alarm) |

## Limitations & Scope

- Synthetic self-contained fixtures only; not organizer-supplied data or real historical malware.
- Scanned archive bytes were never installed, imported, built, or executed.
- AI assistance (Gemini) was used to help design the manifest and harness; all runs were executed locally.
