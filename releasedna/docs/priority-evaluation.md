# ReleaseDNA detector evaluation

Generated: 2026-11-19T04:37:11.041139+00:00 | Engine: 0.1.3

Small convenience sample; public releases are presumed benign, not malware-free ground truth. No package code was executed.

| Measure | Result |
| --- | --- |
| Harmless tampering detected (exact rule + path) | 11/12 (91.7%) |
| Public-release alert rate (false-positive proxy) | 2/8 (25.0%) |
| Public releases inconclusive | 5/8 (62.5%) |
| Public releases CLEAN | 2/8 (25.0%) |
| Controlled benign fixtures alerted | 0/3 (0.0%) |
| Public retrieval/analysis errors | 0 |

INCONCLUSIVE is an abstention, not a successful clean classification. Detection requires the expected rule at the mutated path, not an unrelated baseline alert.

## Public releases

| Package | Split | Verdict | Findings | Generated outputs awaiting verification |
| --- | --- | --- | --- | --- |
| npm:is-number@7.0.0 | development | CLEAN | 0 | 0 |
| npm:picocolors@1.1.1 | development | INCONCLUSIVE | 2 | 0 |
| npm:clsx@2.1.1 | development | INCONCLUSIVE | 0 | 5 |
| npm:mitt@3.0.1 | development | INCONCLUSIVE | 0 | 4 |
| npm:ms@2.1.3 | holdout | CLEAN | 0 | 0 |
| npm:nanoid@5.1.5 | holdout | REVIEW | 7 | 0 |
| npm:tiny-invariant@1.3.3 | holdout | INCONCLUSIVE | 0 | 7 |
| pypi:packaging@25.0 | holdout | INCONCLUSIVE | 0 | 0 |

## Harmless tampering cases

| Fixture | Expected evidence | Detected | Verdict |
| --- | --- | --- | --- |
| added-install-hook | INSTALL_SCRIPT_CHANGED at `package.json` | YES | REVIEW |
| modified-runtime-source | UNEXPLAINED_CODE at `index.js` | YES | REVIEW |
| added-process-indicator | PROCESS_EXECUTION at `helper.js` | YES | REVIEW |
| added-network-indicator | NETWORK_ACCESS at `network.js` | YES | REVIEW |
| encoded-eval-indicator | DYNAMIC_EXECUTION at `encoded.js` | YES | REVIEW |
| native-binary-marker | BINARY_CHANGED at `helper.bin` | YES | REVIEW |
| unexpected-executable | EXECUTABLE_ADDED at `fixture-helper.sh` | YES | REVIEW |
| dependency-change | DEPENDENCIES_CHANGED at `package.json` | YES | REVIEW |
| missing-entrypoint | MISSING_ENTRYPOINT at `index.js` | YES | REVIEW |
| altered-map-source | SOURCEMAP_SOURCE_MISMATCH at `dist/mitt.js.map` | YES | INCONCLUSIVE |
| payload-with-genuine-map | PROCESS_EXECUTION at `dist/mitt.js` | YES | INCONCLUSIVE |
| quiet-generated-modification | UNEXPLAINED_CODE at `dist/mitt.js` | NO — coverage gap | INCONCLUSIVE |

## Limits

- `quiet-generated-modification` is intentionally included: signature-free emitted-code changes can escape current rules. It is a false negative for detection, although the scan remains INCONCLUSIVE rather than CLEAN.
- Source maps and build declarations explain why output exists; they do not prove emitted-code equivalence. Matching maps never disable capability checks.
- Original development/holdout labels are historical. Both sets informed version 0.1.3; this reused corpus is not a fresh independent holdout.
- Cases are pinned historical versions and a convenience sample, not a claim about current ecosystem-wide prevalence or recall.
- No real malware corpus was used. Mutations are harmless text/metadata and are never executed.
- Full path-level evidence, diffs, hashes, source matching and error reasons are in the sibling JSON report.
