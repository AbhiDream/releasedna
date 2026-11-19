# Remote Docker deployment and honest verification status

Updated 20 November 2026. The requested deployment target is a remote service, not a Python web server on the user's laptop. The old host server was stopped after checking that no queued/running jobs remained. No new permanent host server was started.

Live deployment: [releasedna.onrender.com](https://releasedna.onrender.com), Render Free Docker, one instance, manual deployments. Tested application revision: `c560bc9`. See [live evidence](render-smoke-evidence.json). The workspace key is managed in Render Environment; do not commit or share it publicly.

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

## Optional Groq explanations

The backend already supports Groq `openai/gpt-oss-20b`. The root Blueprint declares `GROQ_API_KEY` with `sync: false`, so its value is never stored in Git. For a **new** Blueprint, Render asks for the value during setup. For the existing `releasedna` service, Render does not prompt for newly added `sync: false` variables during Blueprint sync: open **Service → Environment**, add `GROQ_API_KEY` with the value from your Groq console, save and deploy. Keep the key out of chat, the repository, frontend settings and build logs.

After deploy, unlock the workspace in the frontend and open a completed scan. The **Explain findings** button becomes available when `/api/explanation/config` reports configured. A live explanation call is the verification; the model receives at most 30 saved finding IDs, paths and detector-authored messages, not archive contents or diffs. It cannot write to scan results or alter score/verdict. Without the key, the button stays unavailable and no Groq request is made.

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

## Verification record — 20 November 2026 IST

| Requirement | Status | Evidence / limit |
| --- | --- | --- |
| Remote Docker, laptop server stopped | PASS | Render reports Docker/Free, successful image deployment and healthy HTTPS service. No listener on laptop port 8000. |
| Backend tests | PASS | 109 tests in 9.575s in the project Windows environment; the final Render Docker build also passed its offline test gate. An earlier attempt with the system Python failed imports because it lacked project dependencies; it is not counted as passing. |
| Sequential queue | PASS | Remote npm, PyPI and text jobs completed; sampled timeline had at most one running job. Regression tests cover FIFO, capacity and failure recovery. |
| Official npm scan | PASS | is-number@7.0.0: CLEAN/0; artifact 4, source 15, unique paths 15, identical 4, added 0, removed 11, changed 0; official digest and release timestamp available, source corroborated. CLEAN retains its limited definition. |
| PyPI scan | PASS with uncertainty | packaging@25.0 completed with 72 identical files. Source manifest cannot statically establish its dynamic version, so the verdict remains INCONCLUSIVE and confidence candidate. No malware-free or provenance claim. |
| Text differences | PASS | API and actual frontend uploads detected SHELL_PIPELINE at build.txt line 2, risk 30, exact diff. User-supplied identity remains INCONCLUSIVE. |
| Frontend | PASS | Hosted unlock, batch submission, completed history, text uploads, expanded diff, evidence JSON download and corpus HTML download exercised. Groq button explicitly unavailable without key. JavaScript syntax check passed. |
| Access gate and evidence routes | PASS | All seven tested protected HTML/JSON/schema routes return 401 without key and 200 with key; exact endpoint checks recorded in JSON. |
| Container boundary | PASS for observed controls | Non-root runtime and Linux address-space limits observed. Writable root, absent Docker marker, enabled network; no claim of Compose-level flags or a separate container per package on Render. |
| Durable cloud persistence / continuous monitoring | BLOCKED on Free | Redeploy reset the scan database as disclosed. Persistent hosting remains a separate option. Monitor only operates while the service is awake. |
| Groq live narration | BLOCKED | No key, per user preference. Integration and explicit unavailable state retained. |
| PDF visible/white-text audit | PASS | See pdf-injection-audit.md; embedded AI-targeted text is not treated as specification authority. Historical influence cannot be ruled out completely. |

## Deployment fixes and repeatable smoke check

The first remote run returned INCONCLUSIVE because GitHub REST was rate limited on the shared hosting IP; it was recorded as a failed clean-baseline check. Source resolution now supports bounded public Git HTTPS ref advertisements when REST reports a rate limit, including peeled annotated tags, conflicting-tag rejection, and unchanged manifest/gitHead confidence checks. This follows [Git's public HTTP ref-discovery protocol](https://git-scm.com/docs/http-protocol). No GitHub credentials or Git subprocesses are used. The final successful remote npm and PyPI scans both exercised this fallback (`resolution_transport: git_https_refs`), in addition to offline regression tests and a live public ref-discovery check.

Evidence Lab files are now bundled in the image independently of ephemeral scan storage. The structural corpus is rerun offline during the image build. Public evaluation reports retain their original 19 November timestamps and are explicitly labelled recorded snapshots; they are not represented as new provider evaluations. A detector fingerprint mismatch prevents the bundle build. False alarms and misses remain visible.

Run `deploy/verify_remote.py` against the deployed HTTPS origin with `RELEASEDNA_API_TOKEN` in the environment. It creates two registry jobs and one harmless text comparison, checks authentication and serial states, validates the baseline/text finding, and exports full evidence without printing the key. This is a small smoke test, not an accuracy benchmark or persistent-storage test.

```powershell
python releasedna/deploy/verify_remote.py https://releasedna.onrender.com --output remote-verification.json
```

For the UI demo: unlock the workspace; queue `npm,is-number,7.0.0` and `pypi,packaging,25.0`; use Text files to compare `normal` with `normal` plus a harmless `m4_syscmd([printf fixture])` line; expand View diff and download the JSON. Nothing in the input text is executed. Download important scan evidence before the free instance restarts.
