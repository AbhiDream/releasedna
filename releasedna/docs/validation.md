# Milestone 1 validation — 19 November 2026 (Asia/Kolkata)

Historical initial validation. The subsequent [Phase 1 hardening audit](phase1-hardening-report.md) documents the current API, 44-test suite, frontend and restart checks.

Executed on Windows with Python 3.13.1. A fresh virtual environment installed the project's three pinned direct dependencies successfully. All 30 unittest cases passed there. Starlette emits a test-client httpx deprecation warning; it does not fail tests or affect scanner HTTP requests. Transitive versions are recorded in requirements-lock.txt.

| Check | Observed result |
| --- | --- |
| Live CLI: npm is-number 7.0.0 | CLEAN, 0 findings, 4 identical artifact files; source tag 7.0.0, commit 98e8ff1da1a89f93d1397a24d7413ed15421c139 |
| Live CLI: PyPI packaging 25.0 | INCONCLUSIVE, 0 findings, 72 identical files; source tag 25.0 found, dynamic version not statically corroborated; 7 added files |
| Real HTTP POST /api/scans for is-number 7.0.0 | HTTP request completed; CLEAN; 19 combined artifact/source files inspected |
| Synthetic archive baseline | CLEAN, score 0 |
| Synthetic modified archive | HIGH_RISK, score 80; INSTALL_SCRIPT_CHANGED and PROCESS_EXECUTION |
| Docker | Not run: docker command unavailable |

Live reports are in ignored data/ and can be regenerated with the README commands. These are two compatibility samples, not a statistically meaningful false-positive benchmark or an evaluation on recent releases. Organizer-provided tampered archives were not available. No detection-recall claim is made.

Automated coverage includes path traversal, special links, case collisions, per-member and download bounds, redirect host revalidation, digest mismatch, input validation, source identity/tag disagreement, network failure, uncertain-source status, capability deltas, generated-directory distrust, source-map mismatch, executable changes, API concurrency and the shared fixture pipeline.
