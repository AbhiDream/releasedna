# ReleaseDNA 0.1.3 — priority verification

This iteration scores added/changed non-code content, inspects text and binary byte views for script/capability indicators, and reports new high entropy (at least 1 KiB, >=7.5 bits/byte and >=0.5 increase for modified files). Evidence includes paths, line/byte locations, diffs and hashes. Identical content is not rescored. Entropy is not proof of maliciousness, and compressed payloads are not recursively decoded or executed.

## Measured results

| Check | Result | Evidence / limits |
| --- | --- | --- |
| xz-style structural fixtures | PASS: 7/7 exact-rule/path detections | Changed/added m4, shell, disguised data, high-entropy and low-entropy blobs |
| debug-style structural fixtures | PASS: 4/4 | Process indicators and an installation hook; no live malware |
| Synthetic hard-negative FPR | 3/4 (75%) | Legitimate new docs, compressed data and changed regex code still produce generic difference alerts; unchanged macro does not |
| Public release alert-rate proxy | 2/8 (25%), previously 3/8 (37.5%) | picocolors and nanoid still alert; 5/8 INCONCLUSIVE, 2/8 CLEAN, 1/8 REVIEW |
| Original mutation suite | 11/12 (91.7%) | Quiet generated-code modification remains a known miss |
| Original benign controls | 0/3 alerts | No certified ecosystem-wide FPR claim |
| Regression suite | PASS: 73 tests | Detector, metadata, queue, persistence, ETag/dedup, retry, model immutability and API paths |
| Frontend | PASS | JS syntax; real nanoid@5.1.5 scan, anomaly badge, corpus evidence and missing-key UI inspected |
| Registry monitor | PASS | Real npm 200 -> conditional 304; 15-version initial baseline creates no historic scans; watch survives backend restart |
| Model provider live inference | BLOCKED / intentionally deferred | User chose no API key. Mocked valid/invalid output, cache and immutable report checks pass |

The structural fixture generator is a small controlled demonstration, **not detection of the historical xz or debug compromise**. The same four controls are shared across family rows and must not be summed twice. TPR requires the specified rule on the modified path. FPR counts any finding in a labeled benign control, including low-score review findings. There are no hidden score thresholds that discard false positives.

Both original development and holdout releases informed this iteration. Their labels are retained for comparison, but this is now a reused development corpus, not an independent holdout. The initial strict non-code pass raised public alerts to 4/8. Narrow schema/template-based metadata explanations reduced this to 2/8; the final snapshot is [priority-evaluation.json](priority-evaluation.json). Full structural evidence is [priority-adversarial.json](priority-adversarial.json).

## False-alarm changes and remaining boundaries

- Dev configuration and unreferenced `bin/`, `tasks/`, and `scripts/` omissions are explained. Declared entrypoints (including literal install-hook file arguments), explicit files inclusion, and detected JS/Python imports take precedence. Python syntax parsing is bounded to 256 KB per file. Dynamic imports and all packaging semantics are not resolved.
- `.exec(` property calls no longer trigger the dynamic-execution rule. Changed executable code can still legitimately receive UNEXPLAINED_CODE; the hard-negative corpus deliberately exposes that distinction.
- Declared compiled output is paired with source-map `sourcesContent`; adjacent maps work without a sourceMappingURL comment. Exact embedded bytes are checked against repository files. No mapping or emitted-code equivalence is claimed.
- `.d.ts` outputs expose unique `src/*.ts` basename candidates; collisions remain ambiguous. This is pairing evidence, **not a TypeScript type-equivalence verifier**.
- Added pytest support templates must match known normalized hashes; test-cache values must have the expected JSON shape. Only a minimal `{ "type": "module" }` marker under an explicitly declared ESM import/module output is explained. Added keys, arbitrary blobs, build macros and capability indicators still alert. Modified existing metadata is not automatically exempted.
- No builds or scanned package code run. Marker strings and synthetic bytes remain data. Quiet compiled changes and benign compression remain unresolved detector limitations.

## Reproduce

From `releasedna/backend`:

```powershell
..\.venv\Scripts\python -m unittest discover -s tests -q
..\.venv\Scripts\python -m app.adversarial_corpus
# If the official-release cache is missing, capture it first:
..\.venv\Scripts\python -m app.evaluation capture
..\.venv\Scripts\python -m app.evaluation run --include-fixtures
```

Two offline public/fixture replays matched after excluding the generation timestamp. Reports include detector hashes. The corpus generator is deterministic and traverses the same bounded archive reader and comparator as production scans.

Open `/corpus` for the judge demo, expand `xz-script-m4-build.m4`, and inspect SHELL_PIPELINE at line 2 / byte 31 plus the exact diff. `/evaluation` shows the separate public-release and original fixture results. The ivory anomaly badge signifies a finding, not proven malware.

## Monitor

Use the frontend's Release monitor form, or `POST /api/monitor` with `{ "ecosystem":"npm", "name":"is-number" }`. npm and PyPI are supported. First poll seeds existing versions. Subsequent new versions queue scans and persist `new_release` then `scan_result` alerts in SQLite. `/api/monitor` lists watches and the most recent 100 alerts; `POST /api/alerts/{id}/read` marks an alert read; `DELETE /api/monitor/{id}` stops watching.

Polling runs every five minutes per watch while the backend is running, using If-None-Match when an ETag exists. Limits: 50 watches, 10 checks per scheduler batch, bounded 8 MiB metadata, one worker and 20 pending scans. Full queues preserve unseen versions and clear the ETag for retry. Dedup and queued-scan insertion share one database transaction. Restart preserves baseline and dedup records. Poll errors appear on the watch and retry after five minutes. Same-version republishing is not detected; the monitor tracks new version identities. Alerts stay local in the UI/database; no email or external message service is used.

## Optional explanation model

Configure `GROQ_API_KEY` in the backend process environment and restart. Default: Groq `openai/gpt-oss-20b`. No key is bundled, and there is no paid-model fallback. Use a Groq free-plan account and its provider-side limits; application code cannot guarantee account billing policy. Supported model and quota references: [Groq models](https://console.groq.com/docs/models), [rate limits](https://console.groq.com/docs/rate-limits).

Click **Explain findings · Groq** on a completed scan. This sends at most 30 saved finding IDs, paths and bounded detector messages, not source files/diffs. The model returns plain-language explanations keyed to existing finding IDs. Unexpected keys (including a score), missing/unknown IDs and oversized replies are rejected. Text is rendered via textContent. Prompted paths/messages remain untrusted data; model prose is advisory and can be wrong.

The endpoint has no scan-write operation: it hashes the saved report and stores narration in a separate table/cache. Tests verify the persisted result is byte-equivalent before and after valid output, invalid output and missing configuration. No request is sent without the key. The model is outside the detector and monitoring decision paths.

## Git workflow

At the start, the GitHub API returned no existing PRs. The two earlier engine/hardening commits were already on main; this work does not rewrite that history. The previously unmerged evaluation commits and this iteration are included in the new feature PR. Local checks run offline tests, corpus generation and frontend syntax checks. GitHub rejected workflow upload because the saved token lacks the workflow scope. A ready workflow is retained as `github-checks.yml.example`; hosted CI is BLOCKED and was not run. No token permissions were changed. Remote provider inference and a naturally occurring future release remain untested.
