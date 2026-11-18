# Phase 1 verification and hardening

Verified 19 November 2026 (Asia/Kolkata). Phase 2 has not started.

| Requirement | Result | Evidence |
| --- | --- | --- |
| 1. Explain and expose file metrics | PASS | Live scan: artifact 4, source 15, unique comparison paths 15, identical 4, added 0, removed 11, changed 0. Legacy total 19 counts both sides of matching paths. Regression asserts all metrics. |
| 2. Improve missing-file classifications | PASS | Development, tests, documentation, runtime, entrypoint, explicit packaging exclusion and unexplained categories. Source/artifact entrypoints and local shipped-code references override exclusions. Tests cover missing entrypoints, runtime omissions, unknown data, literal files lists and complex-ignore abstention. |
| 3. Persist job states and retrieval API | PASS | POST 202 creates a durable job; GET by ID and paginated history work. Asynchronous worker exposes queued/running/completed/failed. Bounded queue, second-worker exclusion and API validation tested. Actual process interruption marked the running job failed and resumed the queued job. |
| 4. Persistence across backend restart | PASS | Browser-created scan survived two actual process restarts. Raw GET response before/after the second restart was byte-identical, SHA256 e6f4d68b485fe94b4d83420ae25717771292e0c6aeacb879e10bd76e2f5a24b4. Separate new-app-lifespan regression also passes. |
| 5. Precise CLEAN and independent trust claims | PASS | API/report/frontend say “No suspicious differences detected within the available analysis scope.” Source confidence and identity corroboration are separate from registry digest verification; build_provenance_verified is false. |
| 6. npm publication metadata | PASS | Full official packument time[7.0.0] returned 2018-07-04T15:08:58.238Z. Version-only metadata lacked this field. Missing/bad metadata yields null plus a reason; created/modified are never substituted. |
| 7. Regression coverage | PASS | Real is-number artifact/source fixture plus adversarial variants cover matches, omissions, counts, confidence, missing metadata and persisted reports. Full suite passes. |
| 8. Actual frontend integration | PASS | Browser submitted is-number@7.0.0 using the frontend form, observed RUNNING then CLEAN, viewed all metrics, source confidence, digest and timestamp. Reloaded history after restart and reopened original result. Invalid input and interrupted-job error display also checked. |
| 9. Backend/frontend/end-to-end verification | PASS | 44 backend tests passed; node --check frontend/app.js passed; live browser-to-API-to-npm/GitHub scan completed; UI visually inspected in the available browser viewport. |

## Reproducible evidence

Live frontend scan ID: `78661025-f958-4812-a50d-7d29cb0fd209`.

Matched tag: `7.0.0`. Source commit: `98e8ff1da1a89f93d1397a24d7413ed15421c139`. Result: CLEAN, score 0, no suspicious findings. Source confidence: corroborated, not cryptographic build provenance.

Crash test: interrupted `4dbfb217-0091-40a0-b8c9-f567219289fc` became failed with a restart explanation. Queued `e2a6df93-e441-4649-91aa-9841bac1bb36` resumed and completed after restart. Existing completed evidence remained intact.

Local ignored evidence: `data/phase1-browser-scan.json`, `data/restart-results.json`, `data/persistence-before.json`, `data/persistence-after.json`, `data/phase1-frontend-proof.png`. The first PowerShell JSON export normalized timestamps to local timezone; the final persistence comparison used raw HTTP bytes to avoid this serialization artifact.

Commands: from backend, `..\.venv\Scripts\python -m unittest discover -s tests -v`; from project root, `node --check frontend/app.js`. Frontend is buildless HTML/CSS/JavaScript, so there is no framework build command to report.

## Limits and remaining blockers

Docker runtime verification remains BLOCKED because Docker is unavailable. Docker files were updated to include the frontend and a persistent data volume, but container execution is not marked passed. No public deployment, monitoring, full dashboard redesign or AI layer was added.

Missing-file logic is deliberately limited: it does not implement all npm glob/negation/nested-ignore semantics, dynamic runtime dependencies or Python dependency graphs. A positive convention-based explanation is not a proof of runtime completeness. Static capability matching is heuristic. Full-package npm metadata is bounded by the existing download limits, so very large packuments may leave publication time unavailable with an explicit reason.

The API is local-only and single-worker. Keep one process per database; no authentication or production multi-tenant service guarantee is implied. SQLite history is durable, but no automatic retention/deletion policy is implemented. CLI JSON and pre-hardening reports are not automatically imported into the database. Browser checks used the available in-app viewport, not a cross-browser/device matrix.

Starlette's existing httpx test-client deprecation warning remains; tests pass. No package code was executed during the scans or fixture tests.

## Primary references

- [npm metadata format](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md): package-level publication times.
- [npm package.json files and entrypoints](https://docs.npmjs.com/cli/configuring-npm/package-json/): packaging declarations and default main.
- [npm files and ignores](https://github.com/npm/cli/wiki/Files-%26-Ignores): why conservative handling is needed for complex exclusions.
