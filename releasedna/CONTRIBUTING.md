# Two reserved contributor PRs

These are genuine pending contributions. The contributors should author their own commits and open their own PRs. Forking the public repository is sufficient; no new repository access is required.

| Contributor | Reserved scope | Suggested branch |
| --- | --- | --- |
| [Sanskriti6Singh](https://github.com/Sanskriti6Singh) | First-time-user onboarding, independently verified setup and screenshots | `docs/first-run-guide` |
| [kirtisihag-1808](https://github.com/kirtisihag-1808) | Independently authored unseen corpus, preregistered expectations and evaluation write-up | `test/independent-corpus` |

## PR 1 — first-run guide

Create `docs/quickstart.md` and `docs/images/` screenshots from a fresh checkout. Test setup on the contributor's own machine. Document the official-registry scan, harmless local archive comparison, persisted history, unavailable model state, and interpretation of INCONCLUSIVE. Include prerequisites and real troubleshooting observed during setup. Record the OS, Python version, commands and successful result IDs. Add a five-minute judge walkthrough and link the guide from README. Do not merely copy the README or claim platforms that were not tested.

Acceptance: a new user can start the backend, scan is-number@7.0.0, view file evidence and download JSON following only the guide. Include baseline and anomaly screenshots with provenance disclaimers visible. Keep changes in docs/ and the README link so this PR stays independent.

## PR 2 — independent evaluation

Create `backend/evaluation/contributor-corpus.json`, a new fixture generator/test module, and `docs/independent-evaluation.md`. First commit case identities and expected rule/path outcomes **before** running the detector. Add at least six harmless mutations across both ecosystems, including non-code build files and generated output, and six benign controls. Choose inputs not already in either shipped corpus. Include real release dates, archive hashes and source commits where available. Use `File`, `pack`, and `compare` helpers; never install, import, build or execute scanned contents. Keep fixtures small and inert.

Then freeze the detector commit, run once, and report exact-rule-plus-path TP/FN, FP/TN, error counts and abstentions. Include failures and a per-case explanation. Do not change detector rules in the same evaluation PR. Distinguish independently authored synthetic fixtures from organizer-provided samples or real historical malware. Add regression tests for accounting and repeatability if the new harness changes those behaviors.

Acceptance: another contributor can reproduce the table; identities and expected outcomes predate the run; no false negatives/false positives are deleted. Organizer fixtures are not available yet and must not be invented.

## Branch and PR workflow

1. Fork `AbhiDream/releasedna`, clone your fork, and add the original as `upstream`.
2. Fetch upstream and branch from its latest main using the name above.
3. Implement only the reserved scope, run relevant checks and commit under your own Git identity.
4. Push to your fork and open a PR targeting `AbhiDream/releasedna:main`.
5. Describe the contribution, exact commands/results, screenshots or corpus metrics, and limitations. Wait for review before merge. Never push directly to upstream main.

Backend check from `releasedna/backend`: `..\.venv\Scripts\python -m unittest discover -s tests -v`.

Frontend syntax check from repository root: `node --check releasedna/frontend/app.js`.

Do not commit credentials, downloaded package caches or the scan database.
