# ReleaseDNA 0.2 — PS2 verification

Verified 19 November 2026 on Windows / Python 3.13. This prototype demonstrates package/source differences with evidence. It does not establish malware freedom, cryptographic build provenance, arbitrary transpilation equivalence, or competition placement.

## Delivered in this PR

- Local tar/ZIP/wheel artifact and source comparison through the actual frontend, API and CLI; wrapper/prefix controls, bounded persistent uploads, queued jobs and evidence download.
- Separate trusted inspection processes with a wall deadline; POSIX resource-limit configuration. No downloaded package is installed, imported, built or executed.
- JavaScript syntax signatures and Python AST comparison preserve literals and structure while explaining comment/location-only changes. Source-map trailer statements are scored. The former quiet-append fixture is now detected.
- Removal-only development metadata is explained when repository declarations support it. Runtime fields/lifecycle hooks remain protected. Documentation changes still undergo capability/entropy checks, and declared runtime paths are not exempted.
- Explicit missing-tag finding and trusted registry/build adapter interfaces. Build explanation providers cannot disable capability rules or assert verified equivalence.
- Responsive inspection desk, clear artifact/source trust separation, local archive form, searchable/filterable file table, exact diffs, persisted history, model-unavailable state and ivory anomaly badge.
- Two genuine contribution scopes reserved for Sanskriti6Singh and kirtisihag-1808 in CONTRIBUTING.md. Their work and PRs have not been fabricated or completed on their behalf.

## Measured detector results

| Corpus | Result | Interpretation |
| --- | --- | --- |
| Reused public npm/PyPI releases | 1/8 alerted (12.5%); 5/8 INCONCLUSIVE; 2/8 CLEAN; 0 errors | Previously 2/8 alerts. Presumed-benign alert proxy, not certified false-positive ground truth. |
| Reused harmless tampering | 12/12 detected by expected new rule and exact path | Previously 11/12. Development recall, not unseen recall. |
| Original benign controls | 0/3 alerted | Small controlled sample. |
| xz-style structural fixtures | 7/7 detected | Not real CVE exploit validation. |
| debug-style structural fixtures | 4/4 detected | Not real historical debug malware. |
| Hard benign structural controls | 2/4 alerted (50% FPR) | Previously 3/4. New random compressed bytes and unexplained regex code still alert. |
| Fresh public holdout | 2/5 alerted (40%); 3/5 INCONCLUSIVE; 1/5 CLEAN; 1 additional error out of 6 selected | Minimal-false-alarm objective is not achieved. |

Fresh identities were committed at `d003eaf` before detector changes. Detector implementation was frozen at `f11248c` before the fresh capture. No detector rules were tuned after seeing these results. Reports bind named detector files with a portable SHA256 and retain errors/abstentions. Parser versions are pinned. The fresh sample is a convenience sample, not random or independently selected; its versions were latest at selection, not uniformly recent publications. eventemitter3 and idna have 2026 publication dates; the other successful captures are older. attrs failed because no supported unambiguous GitHub source was resolved.

Evidence: [reused public/fixture JSON](submission-evaluation.json), [readable table](submission-evaluation.md), [structural corpus JSON](submission-adversarial.json), [fresh JSON](fresh-evaluation.json), [fresh table](fresh-evaluation.md). Historical reports remain available and are not overwritten to hide earlier misses.

## PASS / FAIL / BLOCKED against PS2

PASS means the stated demonstrated scope was exercised. FAIL means the full criterion is not yet satisfied, even if partial functionality exists. BLOCKED means required external inputs/environment are absent.

| Requirement | Status | Evidence / remaining limitation |
| --- | --- | --- |
| Fetch an exact npm/PyPI version and compare matching source | PASS | Official registry digest + GitHub tag/commit/manifest evidence; live npm scan and both ecosystems in public evaluations. GitHub-only resolution and dynamic versions remain limited. |
| Explain every legitimate compiled/generated/version-stamp difference with few alarms | FAIL | Source-map sourcesContent, declaration pairing, syntax signatures and packaging explanations work; arbitrary bundles/version stamps remain unverified. Fresh public alert proxy is 40%. |
| Flag install hooks, obfuscation indicators, non-code build artifacts and missing tags | PASS | Regression tests and exact-path controlled corpus evidence. Heuristics are incomplete and not proof of malicious intent. |
| Watch packages, avoid excessive registry load and alert on suspicious releases | PASS | Existing persisted watchlist, ETag/304 polling, deduplication, backoff, bounded queue and local alerts; regression tests. Requires running backend. |
| Add ecosystem/build styles without rewriting comparison | PASS | Trusted adapter protocols and substitution tests; new ecosystem still requires endpoint validation and API/CLI exposure. No arbitrary plugin code from packages. |
| Test real releases and publish transparent metrics | PASS | 8 reused and 6 newly selected public cases, errors retained, dated captured metadata and separate holdout report. |
| Detect every organizer-provided tampered copy | BLOCKED | Organizer archives have not been supplied. Local archive input is ready. Synthetic cases cannot substitute for these. |
| Eburnean “anomaly spotted” highlight | PASS | Actual local xz-style comparison shows ivory badge, SHELL_PIPELINE at m4/build.m4 line 2 and unified diff. |
| Safe artifact inspection inside verified OS isolation | BLOCKED | Non-execution, archive limits and process timeout tested. Docker is absent; process separation alone is not a security sandbox. Windows OS memory cap is absent. |
| Advanced diffing / arbitrary semantic build equivalence | FAIL | Syntax-preserving comparison and source-map context are implemented; arbitrary generated-code modifications can still escape, especially before the trailer. |
| Previously unseen tampered packages with minimal false positives | BLOCKED | Independent contributor corpus is reserved; organizer corpus absent. Current development recall is not unseen recall. Hard-control false positives remain high. |
| Optional open-weight narration | BLOCKED (live call) | Groq gpt-oss-20b integration and immutable-score tests pass. No API key by user choice; frontend shows unavailable. Not required for deterministic scans. |
| PR-based integration / hosted CI | PASS / BLOCKED | Feature branch and PR workflow; no direct main push. Hosted Actions cannot be installed with the current credential's missing workflow scope; template is provided. Local checks below were actually run. |

## Execution evidence

- Backend: `python -m unittest discover -s tests -q` — **86 tests passed**, final run 4.904 seconds. Includes archive limits/traversal, missing-file classification, source confidence, metadata, monitor, immutable narration, syntax, process timeout, adapter substitution, local upload queue and restart persistence. A dependency deprecation warning is present; no tests skipped or silently marked passed.
- Frontend: `node --check releasedna/frontend/app.js` — PASS. HTML ID uniqueness and `git diff --check` — PASS. No frontend framework build is required; this is static HTML/CSS/JS.
- Actual browser registry form: `is-number@7.0.0`, scan `68d6123c-b4d6-49de-a9df-df372127eb53` — completed, CLEAN/0, 4 artifact files, 15 source files, 15 unique paths, 4 identical, 11 removed. Publication timestamp and official digest displayed.
- Actual browser local form: uploaded generated xz-style artifact/source archives, scan `c5c30ce4-fdc9-467d-9d73-f80adc34f025` — completed, INCONCLUSIVE/30 because identity is user-supplied, with exact SHELL_PIPELINE evidence. Path search, suspicious filter, expanded diff and JSON download exercised. The fixture text was never executed.
- CLI local comparison of the same pair — INCONCLUSIVE/30 and one finding, consistent with the browser. Local hashes are not represented as official registry verification.
- Backend process was stopped/restarted after both jobs completed. Both saved API responses remained exactly equal. `/health`, `/fresh-evaluation` and `/api/evaluation/fresh` returned 200 afterward.
- Browser layout verified at the available 750px viewport. Wider/mobile breakpoints are implemented but an exhaustive device/accessibility audit was not run. Screenshots and transient logs are in ignored `data/`; contributor PR 1 will independently verify onboarding on another machine.

## Remaining work before claiming a strong unseen-detection result

1. Independently authored preregistered corpus and onboarding PRs from the two contributors.
2. Run supplied organizer archives when available; retain failures.
3. Improve build-style/source-resolution coverage using new development cases, then measure a new untouched holdout. Do not relabel this fresh result as untouched after tuning on it.
4. Execute the container isolation checks in an environment with Docker and enable hosted CI with an appropriately authorized workflow change. No permission expansion was attempted.

The working demo is ready; comprehensive low-false-positive coverage and isolation validation are not complete.
