# Architecture and next milestones

`Frontend -> FastAPI -> SQLite job queue -> single worker -> registry connector -> digest verification -> archive inspector -> source resolver -> comparator -> persisted JSON evidence`

The CLI also calls the scan service directly and writes JSON on request. Its results are not implicitly imported into API history. Job state and analysis verdict are independent. The SQLite database stores requests, timestamps, results and error reasons. Startup recovery fails interrupted running jobs and resumes queued jobs. An OS lock enforces one API process per database.

The same inspector and comparator process live archives and synthetic demos. Connector logic is separated from source resolution and analysis. New ecosystems can return the same release metadata and bytes; new comparison rules consume path/File mappings. A single process avoids distributed infrastructure at this stage.

## Current matching policy

Try `v<version>`, `<version>`, and `<package>@<version>` GitHub tags. Peel annotated tags to commits, reject disagreement among candidates, and cross-check npm gitHead. Read the source manifest as data. A tag alone is a candidate; static name/version identity upgrades it to corroborated. For npm monorepos, only an explicit safe registry repository.directory is applied. No fuzzy source mapping silently establishes trust.

## Expected vs suspicious

Exact bytes and executable bits establish identical files. Manifest formatting/registry metadata and standard source-distribution metadata have narrow explanations. Source-only files are classified as development, tests, documentation, packaging exclusions, runtime, entrypoint or unexplained. Entrypoints and detected local imports override exclusion conventions. Supported literal npm files/ignore rules explain exclusions; unsupported complex rules are not treated as proof. Unknown code changes need review; unknown non-code output makes coverage inconclusive. Compiled directory names are never an allowlist. Sourcemap matching is an evidence annotation rather than a clean verdict.

## Planned phases (not implemented)

2. Expand the verification frontend into the full evidence dashboard, strengthen build-style adapters and adversarial corpus. Evaluate recent releases across both ecosystems and measure false positives explicitly. Basic persisted history was pulled into Phase 1 at the user's explicit request.
3. SQLite-backed watchlist, conditional registry requests, backoff/jitter, release deduplication, bounded worker queue and local alerts. Never post automated issues/comments to real projects.
4. Optional local open-weight explanation of immutable findings, attestation-aware source matching, broader artifacts and isolated inspection workers. AI cannot alter scores or evidence.

Each phase must run its own focused tests before progressing. A winning demonstration needs an honest corpus and measurable detection/false-positive results; neither comprehensive attack coverage nor competition placement can be promised from this initial milestone.
