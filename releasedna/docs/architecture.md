# Architecture and next milestones

`CLI / FastAPI -> registry connector -> digest verification -> archive inspector -> source resolver -> comparator -> JSON evidence`

The same inspector and comparator process live archives and synthetic demos. Connector logic is separated from source resolution and analysis. New ecosystems can return the same release metadata and bytes; new comparison rules consume path/File mappings. A single process avoids distributed infrastructure at this stage.

## Current matching policy

Try `v<version>`, `<version>`, and `<package>@<version>` GitHub tags. Peel annotated tags to commits, reject disagreement among candidates, and cross-check npm gitHead. Read the source manifest as data. A tag alone is a candidate; static name/version identity upgrades it to corroborated. For npm monorepos, only an explicit safe registry repository.directory is applied. No fuzzy source mapping silently establishes trust.

## Expected vs suspicious

Exact bytes and executable bits establish identical files. Manifest formatting/registry metadata and standard source-distribution metadata have narrow explanations. Source-only files are reported as omissions. Unknown code changes need review; unknown non-code output makes coverage inconclusive. Compiled directory names are never an allowlist. Sourcemap matching is an evidence annotation rather than a clean verdict.

## Planned phases (not implemented)

2. Evidence dashboard, persistent scan history, stronger build-style adapters and adversarial corpus. Evaluate recent releases across both ecosystems and measure false positives explicitly.
3. SQLite-backed watchlist, conditional registry requests, backoff/jitter, release deduplication, bounded worker queue and local alerts. Never post automated issues/comments to real projects.
4. Optional local open-weight explanation of immutable findings, attestation-aware source matching, broader artifacts and isolated inspection workers. AI cannot alter scores or evidence.

Each phase must run its own focused tests before progressing. A winning demonstration needs an honest corpus and measurable detection/false-positive results; neither comprehensive attack coverage nor competition placement can be promised from this initial milestone.
