# Remote Docker deployment and honest verification status

Updated 20 November 2026. The requested deployment target is a remote service, not a Python web server on the user's laptop. The old host server was stopped after checking that no queued/running jobs remained. No new permanent host server was started.

## Free option: Render Docker demo

The repository-root `render.yaml` defines a **free Docker web service**, one instance, generated workspace access key and no paid disk. It uses the project's Dockerfile, pinned Python dependencies, non-root runtime, and an offline unit-test gate during the image build. The port comes from Render's `PORT` variable. Manual deployment is the default.

This is a demo tier, not durable production hosting:

- Render Free can sleep after 15 idle minutes and restart at any time.
- Its filesystem is ephemeral: history, uploads, watch lists and alerts can disappear on restart/redeploy/sleep. Download evidence JSON before leaving.
- Monitoring works while the service is awake; this is not continuous 24/7 coverage.
- The free instance has limited RAM. Small demos are the initial target; large archive load/OOM behavior has not been verified on Render.

The frontend displays an explicit temporary-storage warning when `RELEASEDNA_STORAGE=ephemeral`. It does not represent a free deployment as persistent.

Provider references: [free service limits](https://render.com/docs/free), [Docker runtime](https://render.com/docs/docker), [Blueprint configuration](https://render.com/docs/blueprint-spec). Railway also supports containers, but a trial is not assumed to be permanently free hosting; the current prepared default is Render Free.

## Deploy after reviewing the PR

1. Review and merge the feature PR into `AbhiDream/releasedna:main`. Main now includes the contributor PRs. A malformed corpus input discovered during integration was repaired with the separately identified prepared experiment; see [recovery details](contributor-corpus-recovery.md).
2. Sign in to your own [Render dashboard](https://dashboard.render.com/). Connect the repository using the provider's normal authorization flow. Never send passwords, OTPs or private API keys in chat.
3. Create a **Blueprint** from the repository's `main` branch and root `render.yaml`. Check that its instance plan is **Free**, runtime **Docker**, and no paid disk is attached before creating it. No paid resource has been created by this work.
4. Wait for the Docker build and health check. The build runs the unit suite; a failed suite must fail the image rather than be reported as passing.
5. In the service's Environment section, retrieve its generated `RELEASEDNA_API_TOKEN`. Enter it in the hosted frontend's **Unlock workspace** form. The key is kept in that browser tab's session storage, sent in the Authorization header only, and never embedded in a URL or committed to Git.
6. Use the assigned HTTPS `onrender.com` URL from any device. The laptop does not run the backend. Do not expose a host dev server as a substitute.

Before merge, a maintainer can explicitly select the feature branch for a preview service; the Blueprint's service `branch` must also be changed from `main` to that exact branch for the preview. Do not accidentally deploy the previous main revision and call it this feature.

The shared access key protects history, uploads, mutation APIs, model requests and evidence pages. It is a small-team prototype access gate, not individual-user authorization or a complete public multi-tenant security design. Protected report links download HTML/JSON with authenticated requests; the API reference link downloads the OpenAPI schema in an unlocked hosted session.

## One package at a time

The persisted worker has concurrency **1**. Registry scans, monitor-created jobs, archive comparisons and direct text comparisons share that worker. The process lock forbids a second worker on the same database. Keep one replica and one Uvicorn worker.

Frontend: open **Official registry → Queue multiple packages** and enter:

```text
npm,is-number,7.0.0
pypi,packaging,25.0
```

Each line is an explicit ecosystem/name/version. `POST /api/scans/batch` validates every entry, then inserts the entire batch atomically or none of it. Capacity is 20 pending jobs including the running job. SQL insertion order preserves FIFO even if timestamps tie or the clock changes. A failed job is saved and the worker proceeds to the next. The live queue shows running/queued entries, and existing history/download behavior remains available.

`GET /api/queue` returns current jobs and concurrency; `GET /api/scans/{id}` returns each job's durable-on-that-filesystem state/result. The usual interrupted-running-job recovery applies only when the database itself survives, such as a persistent volume. It cannot restore a free provider filesystem that was discarded.

## Text files are compared too

Text files inside package archives already receive hash comparison, bounded line diffs and capability/non-code analysis. The new **Text files** tab accepts two standalone UTF-8 files, 1–120,000 bytes each, and a comparison filename. `POST /api/text-comparisons` queues the same operation via uploaded file IDs.

It preserves original byte hashes and reports exact changed lines and heuristic findings. Invalid UTF-8, NUL bytes, oversized data and unsafe paths fail explicitly. Large line counts may reach the existing diff budget and are reported as truncated. Supplied files have unverified source identity and no registry provenance; even identical text does not become a certified clean package. Uploaded text never becomes an instruction or executable program.

## Isolation boundary

Both API and its per-job inspection child run inside the deployed Docker image. The child has a wall deadline and requests Linux CPU/address-space limits. The trusted app reads archive members as bytes without extracting, installing, importing or building scanned packages. No host source directory or Docker socket is mounted by the provided Compose configuration.

The self-managed Compose variant adds a read-only root filesystem, dropped capabilities, no-new-privileges, bounded tmpfs, CPU/memory/PID limits and a named data volume. **Render does not consume docker-compose.yml**, so those exact Compose flags must not be claimed as provider-enforced controls. Render supplies its managed container boundary; actual runtime policy still needs inspection. Network access remains enabled for approved registry/GitHub retrieval and optional Groq narration. Neither configuration is an offline network sandbox, and no claim is made of a fresh disposable Docker container per package.

Reports include observed non-root status, Docker marker presence and root-filesystem read-only status where available. The deployment label comes from configuration and is not an attestation. Container isolation is defense in depth, not permission to execute suspect code.

The container entrypoint refuses root execution and a missing/short access key, checks that the data location is writable, and starts one worker. A provider volume permission failure must be fixed on that volume; do not resolve it by running the analyzer as root.

## Optional durable deployment

`deploy/render-persistent.yaml.example` is an explicit **paid** alternative: 2 GB instance plus 1 GB persistent disk. It is not the default Blueprint. Review Render's current pricing and approve costs before using it. A persistent disk preserves SQLite history and local uploads on ordinary restarts; back up valuable evidence separately. The separate Compose file is also suitable for a controlled Docker host with persistent storage.

Official references: [Render persistent disks](https://render.com/docs/disks), [Render pricing](https://render.com/pricing), [Compose service controls](https://docs.docker.com/reference/compose-file/services/).

## Verification record

| Requirement | Status | Evidence / limit |
| --- | --- | --- |
| Sequential worker + atomic batch | PASS | Regression verifies one running/two queued, FIFO with tied clocks, capacity rollback and continue after failure. |
| Standalone and archived text differences | PASS | Hashes, exact macro line/path, UTF-8, limits, unsafe paths, unchanged bytes and API job persistence tested. |
| Remote workspace access gate | PASS locally | Unauthenticated history, queue, uploads and mutation return 401; valid key works; missing required key prevents startup. |
| Backend suite | PASS | 100 tests, 5.607 seconds on Windows/Python 3.13.1. New tests execute through TestClient and the inspection subprocess, not a deployed Render instance. |
| Frontend checks | PASS statically | `node --check`, unique HTML IDs and literal JS-to-HTML bindings. New controls have not yet been browser-tested against the hosted service. |
| Compose + both Render YAML schemas | PASS | Validated against current official Compose/Render schemas. This does not build or launch containers. |
| PDF visible/white-text audit | PASS | Observed injection documented; neutral badge replaces the matching wording. No claim that all prior influence can be ruled out. |
| Docker image build + runtime controls | BLOCKED | Docker/WSL unavailable locally; remote provider build has not been launched. Dockerfile test command is a gate, not a fabricated passing container run. |
| Hosted frontend / real remote end-to-end scan | BLOCKED | Render account/service deployment needed. No live URL has been fabricated. |
| Free-tier durable persistence / continuous monitoring | NOT SUPPORTED | Deliberate free-tier limitation, clearly shown in UI; persistent tier is optional. |

## Remote acceptance checks still to run

The supplied `deploy/verify_remote.py` runs only when explicitly invoked against your deployed HTTPS origin with `RELEASEDNA_API_TOKEN` in the shell environment. It creates two real package jobs and a harmless text comparison, checks the auth gate, observes serial states, checks the exact text finding, and saves complete results without printing the key.

```powershell
python releasedna/deploy/verify_remote.py https://YOUR-SERVICE.onrender.com --output remote-verification.json
```

Then manually verify the hosted batch/text forms, Downloads and history. Inspect the container observations and provider logs. On a paid persistent service, restart it and compare saved job IDs/results. On Free, treat lost state as the documented limitation, not a passed persistence test. Do not mark any of these remote checks PASS until actually run.
