# ReleaseDNA

Package supply-chain forensics for Catalyst Problem Statement 2.

**Milestone 1: working inspection engine, CLI and HTTP API.** Download an exact npm release or PyPI source distribution, verify its registry digest, match a GitHub source revision, inspect both archives without extracting or executing them, and produce deterministic file-level evidence.

This is an early static analyzer, not a malware-free certification. There is no AI dependency. The dashboard, release monitoring, persistent history, wheel support and optional open-weight explanation layer are future phases.

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

The API documentation is at http://127.0.0.1:8000/docs. `GET /health` returns engine health. `POST /api/scans` accepts:

```json
{"ecosystem":"npm","name":"is-number","version":"7.0.0"}
```

Scans are synchronous and capped at one concurrent scan per API process. Invalid inputs return 422; a busy process returns 429. A completed request can return `INCONCLUSIVE` with a network or inspection error; inspect the report rather than interpreting HTTP 200 as a clean verdict. No arbitrary URL input is exposed. Bind locally: authentication and public-service rate limits are outside this milestone.

## Demo

1. Run the live npm example. Open its JSON: inspect the artifact digest, tag/commit, per-file hashes and counts.
2. Run `python -m app.demo` from `backend`. It packs a controlled baseline and a modified archive, then runs both through the same inspector and comparator used for real releases. The tampered archive adds an install hook and process-execution indicator. **These fixtures are synthetic and are never executed.**
3. Run the PyPI example. Show how uncertainty is retained when a dynamic version or packaging differences cannot be established statically.

No finding or verdict is hardcoded in the demo. The fixtures contain inert code strings as analysis input.

## Verdicts and evidence

- `CLEAN`: source identity is corroborated by a release tag and static package name/version (and npm gitHead when present), inspection completes, and differences are explained without suspicious findings. This is not signed provenance or a malware-free claim.
- `REVIEW`: heuristics or unexplained code differences warrant investigation.
- `HIGH_RISK`: several deterministic indicators reach 70 points; human review is still necessary.
- `INCONCLUSIVE`: source matching or coverage is inadequate, or non-code differences remain unexplained. This overrides the other status; `suspicion_level` and findings remain visible even if risk is high.

Rule weights are in `backend/app/diff_engine/compare.py`. Each rule contributes once per scan, capped at 100. Scores rank review urgency and are not probabilities. Every finding includes artifact/source paths, a rule, changed-line evidence where applicable, and a bounded unified diff. Binary and permission rules use file hashes/metadata rather than invented text lines.

## Security boundaries

Only HTTPS requests to exact approved registry/GitHub hosts are allowed. Every redirect is revalidated; proxy environment settings are ignored. Network requests have timeouts and a scan deadline. Limits: 24 MiB compressed download, 64 MiB expanded archive, 4 MiB per member, 6,000 entries. Links, devices, sparse files, traversal and case-colliding paths fail closed. Archive contents remain in memory; no member is written or imported. Sourcemap paths are never fetched.

The dependency installation above installs this application's dependencies, never the packages being scanned. The scanner contains no package installation, build, require/import of fetched code or subprocess execution path.

The single-process implementation is intended for local evaluation. Python parser operations and archive headers do not have an OS-enforced per-task CPU deadline. Deploying against adversarial traffic requires a resource-limited worker boundary. Compose provides a read-only filesystem, a non-root user, memory/CPU/PID limits and no extra capabilities. Docker execution has not been verified in the development environment because Docker was unavailable.

## Docker

```sh
docker compose up --build
```

## Scope and trade-offs

- GitHub only; repository claims can themselves be attacker controlled. Tags may move. Reports record the observed immutable commit and archive digest.
- PyPI source distributions only. Dynamic versions, setuptools configuration, monorepo mapping beyond npm `repository.directory`, and generated bundles are conservative/partial.
- Source maps supply corroborating evidence only: a matching `sourcesContent` cannot prove the emitted bundle is authentic.
- Regex capability rules can miss aliases or advanced obfuscation and can flag benign code. No claim of complete semantic analysis.
- Repository-only files are shown as packaging omissions. This does not prove the package is functionally complete.
- npm version metadata does not include a publication timestamp; it is explicitly null in this milestone.
- Entirely unchanged files are hash-compared but not malware-scanned. The question answered is release/source divergence.
- No attestation verification, rebuilding, automatic external notifications or public publishing.

## Prior work and differentiation

[npm provenance](https://docs.npmjs.com/generating-provenance-statements), [PyPI attestations](https://docs.pypi.org/attestations/) and [OSS Rebuild](https://github.com/google/oss-rebuild) address provenance and build reproduction. ReleaseDNA focuses on explainable mismatches without executing a build: file identity, new installation hooks, changed capabilities and explicit uncertainty. This complements those systems; it does not replace their provenance assurance.

Connector references: [npm metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md), [PyPI JSON API](https://docs.pypi.org/api/json/), [GitHub commits API](https://docs.github.com/en/rest/commits/commits).

Work lives on `feat/inspection-engine`. No remote has been configured and nothing has been published. Use a reviewed pull request when connecting a public repository.
