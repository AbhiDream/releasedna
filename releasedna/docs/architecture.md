# Architecture and next milestones

`Frontend -> FastAPI -> SQLite job queue -> single worker -> registry connector -> digest verification -> archive inspector -> source resolver -> comparator -> persisted JSON evidence`

The CLI also calls the scan service directly and writes JSON on request. Its results are not implicitly imported into API history. Job state and analysis verdict are independent. The SQLite database stores requests, timestamps, results and error reasons. Startup recovery fails interrupted running jobs and resumes queued jobs. An OS lock enforces one API process per database.

The same inspector and comparator process live archives and synthetic demos. Connector logic is separated from source resolution and analysis. New ecosystems can return the same release metadata and bytes; new comparison rules consume path/File mappings. A single process avoids distributed infrastructure at this stage.

## Current matching policy

Try `v<version>`, `<version>`, and `<package>@<version>` GitHub tags. Peel annotated tags to commits, reject disagreement among candidates, and cross-check npm gitHead. Read the source manifest as data. A tag alone is a candidate; static name/version identity upgrades it to corroborated. For npm monorepos, only an explicit safe registry repository.directory is applied. No fuzzy source mapping silently establishes trust.

## Expected vs suspicious

Exact bytes and executable bits establish identical files. Manifest formatting/registry metadata and standard source-distribution metadata have narrow explanations. Source-only files are classified as development, tests, documentation, packaging exclusions, runtime, entrypoint or unexplained. Entrypoints and detected local imports override exclusion conventions. Supported literal npm files/ignore rules explain exclusions; unsupported complex rules are not treated as proof. Unknown code changes need review; unknown non-code output makes coverage inconclusive. Compiled directory names are never an allowlist. Sourcemap matching is an evidence annotation rather than a clean verdict.

## Current extension boundaries (0.2)

Registry retrieval dispatches through `connectors/adapters.py` and its `RegistryAdapter` protocol. npm/PyPI preserve their validated official endpoints and digest checks. New trusted adapters register in application code; package contents cannot register code. Advertising a new ecosystem in the API/CLI and extending the exact host allowlist are explicit integration steps. Registry and build adapters have substitution tests.

`diff_engine/build_adapters.py` composes static explanation providers. The existing npm provider uses repository declarations and embedded source maps. Additional providers implement `explain(path)` and return evidence; the wrapper forces `equivalence_verified=False`, and all deterministic tampering rules still run. No provider executes builds.

JavaScript uses bounded Tree-sitter syntax signatures; Python uses AST structure. Comments/locations are excluded while literals and structure remain. This explains syntax-preserving transformations, not arbitrary minification or transpilation. Source-map trailer statements are detected; changes before the trailer may still evade rules.

API jobs and both CLIs use a spawned trusted worker with a 150-second wall deadline. Archive reads remain non-extracting. POSIX requests resource limits; Windows lacks an OS memory cap. The process boundary is not network/filesystem isolation. The live Render Free deployment was observed running as a non-root Docker service with a Linux address-space limit. The root filesystem was writable, the container marker was absent, and network access was enabled; this is provider-container execution, not a separately attested sandbox per package. Compose-only restrictions are not claimed as active on Render. See [remote verification](remote-deployment.md).

Local artifact/source uploads are bounded SQLite blobs, referenced by ID and checked transactionally when creating a queued job. Reports record hashes, chosen layouts and unverified user-supplied identity. Completed results survive upload deletion and restart. Official scans use the same persisted queue.

## Historical roadmap (superseded by current verification)

The evidence dashboard, static adapter interfaces, measured corpora, persisted watchlist, conditional polling, deduplication, local alerts and optional Groq open-weight narration are implemented. Attestation verification, general build equivalence and verified container isolation remain outside the demonstrated scope. See submission-verification.md for PASS/FAIL/BLOCKED results.

Each phase must run its own focused tests before progressing. A winning demonstration needs an honest corpus and measurable detection/false-positive results; neither comprehensive attack coverage nor competition placement can be promised from this initial milestone.
