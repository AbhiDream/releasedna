# ReleaseDNA detector evaluation

Generated: 2026-11-19T05:06:06.778662+00:00 | Engine: 0.2.0

Small convenience sample; public releases are presumed benign, not malware-free ground truth. No package code was executed.

| Measure | Result |
| --- | --- |
| Harmless tampering detected (exact rule + path) | not measured |
| Public-release alert rate (false-positive proxy) | 2/5 (40.0%) |
| Public releases inconclusive | 3/5 (60.0%) |
| Public releases CLEAN | 1/5 (20.0%) |
| Controlled benign fixtures alerted | not measured |
| Public retrieval/analysis errors | 1 |

INCONCLUSIVE is an abstention, not a successful clean classification. Detection requires the expected rule at the mutated path, not an unrelated baseline alert.

## Public releases

| Package | Split | Verdict | Findings | Generated outputs awaiting verification |
| --- | --- | --- | --- | --- |
| npm:escape-string-regexp@5.0.0 | fresh_holdout | CLEAN | 0 | 0 |
| npm:kleur@4.1.5 | fresh_holdout | INCONCLUSIVE | 0 | 2 |
| npm:eventemitter3@5.0.4 | fresh_holdout | REVIEW | 5 | 0 |
| pypi:six@1.17.0 | fresh_holdout | INCONCLUSIVE | 1 | 0 |
| pypi:attrs@26.1.0 | fresh_holdout | ERROR | ValueError: Source resolution yielded no archive: No unambiguous supported GitHub repository in registry metadata | — |
| pypi:idna@3.20 | fresh_holdout | INCONCLUSIVE | 0 | 0 |

## Harmless tampering cases

| Fixture | Expected evidence | Detected | Verdict |
| --- | --- | --- | --- |

## Limits

- The source-map trailer rule covers the known quiet append fixture. Arbitrary emitted-code changes before a trailer can still evade detection.
- Source maps and build declarations explain why output exists; they do not prove emitted-code equivalence. Matching maps never disable capability checks.
- Original development/holdout labels are historical. Both sets informed version 0.1.3; this reused corpus is not a fresh independent holdout.
- Cases are pinned historical versions and a convenience sample, not a claim about current ecosystem-wide prevalence or recall.
- No real malware corpus was used. Mutations are harmless text/metadata and are never executed.
- Full path-level evidence, diffs, hashes, source matching and error reasons are in the sibling JSON report.
