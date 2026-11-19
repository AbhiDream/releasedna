# ReleaseDNA

Latest: **0.2 prototype** — bounded local archive jobs, syntax evidence, static build adapters, a redesigned inspection desk and a separate fresh public benchmark. See [current verification and remaining gaps](docs/submission-verification.md), [reused corpus results](docs/submission-evaluation.md), and [fresh public holdout](docs/fresh-evaluation.md). Earlier milestone reports are historical snapshots.

Package supply-chain forensics for Catalyst Problem Statement 2.

**Phase 1, hardened: inspection engine, CLI, durable job API and verification frontend.** Download an exact npm release or PyPI source distribution, verify its registry digest, match a GitHub source revision, inspect both archives without extracting or executing them, and produce deterministic file-level evidence.

This is a static analyzer, not a malware-free certification. Deterministic inspection needs no AI key. Release monitoring and optional Groq narration are implemented; local wheel/ZIP comparison is supported, while official PyPI retrieval uses source distributions. Two independent contributor PRs are reserved in [CONTRIBUTING.md](CONTRIBUTING.md).

Open `/evaluation`, `/corpus` and `/fresh-evaluation` for generated evidence reports. Reused fixture recall is 12/12; reused public alerts are 1/8. Fresh public alerts are 2/5 with one additional source-resolution error. These small samples do not establish ecosystem-wide accuracy. False-positive reduction is not complete.

## Run locally

Python 3.11 or later. From this directory:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd backend
..\.venv\Scripts\python -m app.cli npm is-number 7.0.0 --output ..\data\scan.json
..\.venv\Scripts\python -m app.cli pypi packaging 25.0 --output ..\data\python-scan.json
..\.venv\Scripts\python -m app.demo
..\.venv\Scripts\python -m unittest discover -s tests -v
..\.venv\Scripts\python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ for the scan frontend, or http://127.0.0.1:8000/docs for API documentation. `GET /health` returns engine/worker health. `POST /api/scans` accepts:

```json
{"ecosystem":"npm","name":"is-number","version":"7.0.0"}
```

POST returns **202** with a durable job `id`, a `state` (`queued`, `running`, `completed`, `failed`), and a `Location` header. `GET /api/scans/{id}` returns the job and its `result` when available. `GET /api/scans?limit=50&offset=0` returns paginated history (maximum limit 100). The result's `status` is the analysis verdict, separate from job state. An inconclusive comparison can complete successfully; artifact/download errors fail the job and retain any partial report.

SQLite defaults to `releasedna/data/scans.sqlite3`, independent of the working directory. Set `RELEASEDNA_DB` to override it. A single background worker processes a bounded queue of 20 pending jobs. Invalid inputs return 422; a full queue returns 429. Completed/failed jobs persist across restart; queued jobs resume; a running job interrupted before committing its result becomes failed with an explicit restart reason. Graceful shutdown finishes the active scan. A process-level OS lock prevents two workers from owning the same database. Run one API process, without `--workers`. No arbitrary URL input is exposed. Bind locally: authentication and public-service rate limits are outside this milestone.

The old synchronous API response shape has changed: use `job.result.status`, not `job.status`. CLI JSON output remains a direct report and is not automatically added to API history. Earlier CLI/Swagger JSON files are not silently imported into the new database.

## Demo

1. Run the live npm example. Open its JSON: inspect the artifact digest, tag/commit, per-file hashes and counts.
2. Run `python -m app.demo` from `backend`. It packs a controlled baseline and a modified archive, then runs both through the same inspector and comparator used for real releases. The tampered archive adds an install hook and process-execution indicator. **These fixtures are synthetic and are never executed.**
3. Run the PyPI example. Show how uncertainty is retained when a dynamic version or packaging differences cannot be established statically.

No finding or verdict is hardcoded in the demo. The fixtures contain inert code strings as analysis input.

## Verdicts and evidence

- `CLEAN`: **No suspicious differences detected within the available analysis scope.** This requires corroborated source identity, completed inspection and explained differences. It is not signed provenance or a malware-free claim.
- `REVIEW`: heuristics or unexplained code differences warrant investigation.
- `HIGH_RISK`: several deterministic indicators reach 70 points; human review is still necessary.
- `INCONCLUSIVE`: source matching or coverage is inadequate, or non-code differences remain unexplained. This overrides the other status; `suspicion_level` and findings remain visible even if risk is high.

Rule weights are in `backend/app/diff_engine/compare.py`. Each rule contributes once per scan, capped at 100. Scores rank review urgency and are not probabilities. Every finding includes artifact/source paths, a rule, changed-line evidence where applicable, and a bounded unified diff. Binary and permission rules use file hashes/metadata rather than invented text lines.

`artifact.verified` means only that the downloaded bytes match the official registry digest. `source.confidence` and `source.identity_corroborated` describe revision matching; `source.build_provenance_verified` remains false. The former ambiguous `source.verified` field was removed.

`metrics` contains artifact_file_count, source_file_count, unique_comparison_paths, identical_files, added_files, removed_files and changed_files. The legacy total_files_inspected counts artifact plus source file instances, so shared paths count twice. For is-number: 4 + 15 = 19 file instances, but 15 unique comparison paths. The four difference counters sum to unique paths.

Repository-only files carry `omission_kind`, `omission_rule` and an explanation. Entrypoints (`main`, `exports`, `bin`, etc.) and static relative imports from shipped JavaScript take precedence over exclusions. Literal npm `files` lists and simple root ignore entries can explain exclusions. Tests/docs/development conventions are identified separately. Unexplained runtime omissions trigger review; unknown non-code omissions make the result inconclusive. Complex npm glob/negation/nested ignore semantics, dynamic imports and Python dependency resolution are not fully modeled and are never described as fully verified packaging rules.

## Security boundaries

Only HTTPS requests to exact approved registry/GitHub hosts are allowed. Every redirect is revalidated; proxy environment settings are ignored. Network requests have timeouts and a scan deadline. Limits: 24 MiB compressed download, 64 MiB expanded archive, 4 MiB per member, 6,000 entries. Links, devices, sparse files, traversal and case-colliding paths fail closed. Archive contents remain in memory; no member is written or imported. Sourcemap paths are never fetched.

The dependency installation above installs this application's dependencies, never the packages being scanned. The scanner never installs, builds, imports or executes fetched code. It spawns only its own trusted inspection worker.

Each API/CLI inspection runs in a separate spawned process with a 150-second wall deadline. POSIX workers request CPU/address-space limits; the Windows run has no OS memory cap. This is fault containment, not a filesystem/network sandbox. Compose provides a read-only filesystem, non-root user and resource limits. Docker isolation remains unverified because Docker is unavailable locally. Keep this unauthenticated prototype bound to localhost.

## Docker

```sh
docker compose up --build
```

## Scope and trade-offs

- GitHub only; repository claims can themselves be attacker controlled. Tags may move. Reports record the observed immutable commit and archive digest.
- Official PyPI retrieval uses source distributions; local supplied wheels/ZIPs are supported without registry-verification claims. Dynamic versions, setuptools configuration and generated bundles remain partial.
- Source maps supply corroborating evidence only: a matching `sourcesContent` cannot prove the emitted bundle is authentic. Declared compiled output is `generated_unverified`, with zero points solely for being generated; it prevents a CLEAN verdict until equivalence is established. Strong capability rules still apply.
- Regex capability rules can miss aliases or advanced obfuscation and can flag benign code. JavaScript Tree-sitter and Python AST comparisons explain comment/location-only changes while preserving literal values and program structure. This is not complete semantic equivalence analysis.
- Missing-file classifications use supported declarations, limited static imports and conventions; they do not prove complete runtime dependency coverage.
- npm publication time is read from the official full packument's exact `time[version]` entry. Missing/malformed/unavailable metadata remains null with a reason, never substituted with package `created` or `modified` timestamps.
- Entirely unchanged files are hash-compared but not malware-scanned. The question answered is release/source divergence.
- No attestation verification, rebuilding, automatic external notifications or public publishing.

## Prior work and differentiation

[npm provenance](https://docs.npmjs.com/generating-provenance-statements), [PyPI attestations](https://docs.pypi.org/attestations/) and [OSS Rebuild](https://github.com/google/oss-rebuild) address provenance and build reproduction. ReleaseDNA focuses on explainable mismatches without executing a build: file identity, new installation hooks, changed capabilities and explicit uncertainty. This complements those systems; it does not replace their provenance assurance.

Connector references: [npm metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md), [PyPI JSON API](https://docs.pypi.org/api/json/), [GitHub commits API](https://docs.github.com/en/rest/commits/commits).

Repository: [AbhiDream/releasedna](https://github.com/AbhiDream/releasedna). Previous milestones merged through PRs #1 and #2; new work also goes through branches and PRs. Hosted CI remains unverified; the workflow template is `docs/github-checks.yml.example`.

## Local archive comparison

Choose **Local archives** in the frontend and select an artifact/source pair. Layout controls keep or strip a wrapper and optionally select a subdirectory. Uploads are stored in SQLite (24 MiB each, 256 MiB retained total); remove unused inputs in the panel. Active jobs prevent removal of their inputs. Results persist after input deletion.

From `releasedna/backend`:

```powershell
..\.venv\Scripts\python -m app.local_cli --artifact artifact.tgz --source source.zip --output ..\data\comparison.json
```

`POST /api/uploads` accepts raw bytes and returns an ID. `POST /api/comparisons` takes `artifact_id`, `source_id`, optional name, wrapper layouts (`auto`, `strip`, `keep`) and prefixes. Poll `/api/scans/{id}`. Local identity is user-supplied, never registry-verified provenance.

## Reproduce current evaluations

From `releasedna/backend`:

```powershell
..\.venv\Scripts\python -m app.evaluation capture --include-fixtures
..\.venv\Scripts\python -m app.adversarial_corpus
..\.venv\Scripts\python -m app.evaluation capture --corpus evaluation/fresh-corpus.json --output ..\data\fresh-evaluation.json
```

Capture retrieves archives without installing them. Subsequent `run` commands replay digest-checked caches. Failures remain explicit errors. Committed evidence is under `docs/`; downloaded archives, database and generated dashboards stay under ignored `data/`.

The structural corpus command also writes `data/demo-xz-artifact.tgz` and `data/demo-xz-source.tgz` (plus a debug-style pair). Select these in **Local archives** to demonstrate an actual queued comparison, the ivory anomaly badge, exact changed line, diff and evidence download. They are harmless synthetic analogues, not historical malware or organizer test data.

`GROQ_API_KEY` enables optional narration through `openai/gpt-oss-20b`. Without a key the frontend shows unavailable. Configure it only in the backend environment. Model text never changes saved findings or scores.
