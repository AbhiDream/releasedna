# AI-assisted contributor evaluation

AI-assisted synthetic extension designed with knowledge of current rules; not independent blind validation, public release sampling or organizer data. Expectations and complete input bytes committed before first comparison. No detector tuning in this branch.

Generated: 2026-11-19T05:59:21.274806+00:00

| Measure | Result |
| --- | --- |
| total | 12 |
| evaluated | 12 |
| errors | 0 |
| TP | 5 |
| FN | 1 |
| FP | 2 |
| TN | 4 |
| TPR | 0.8333333333333334 |
| FPR | 0.3333333333333333 |
| inconclusive | 2 |

TP requires the expected NEW rule at the exact path, beyond baseline findings. Errors are excluded from TPR/FPR and retained separately. INCONCLUSIVE is not CLEAN.

| Case | Label | Outcome | Verdict | Evidence IDs |
| --- | --- | --- | --- | --- |
| npm-export-subpath-removed | tampered | TP | REVIEW | F0001 |
| npm-configure-macro-added | tampered | TP | REVIEW | F0001 |
| npm-quiet-change-before-map | tampered | FN | INCONCLUSIVE |  |
| python-relative-module-removed | tampered | TP | REVIEW | F0001 |
| python-process-in-config | tampered | TP | REVIEW | F0001 |
| python-decoder-in-data | tampered | TP | REVIEW | F0001 |
| npm-comment-only-export | benign | TN | CLEAN |  |
| npm-regex-layout-only | benign | TN | CLEAN |  |
| npm-declared-map-and-types | benign | TN | INCONCLUSIVE |  |
| python-comment-only-function | benign | TN | CLEAN |  |
| python-wheel-metadata-control | benign | FP | REVIEW |  |
| python-version-stamp-control | benign | FP | REVIEW |  |

Synthetic known-rule convenience cases, not independent unseen recall or organizer validation. No detector changes were made. Sibling JSON includes complete diffs, baseline findings, hashes and errors.
