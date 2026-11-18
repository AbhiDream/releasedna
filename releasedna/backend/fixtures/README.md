# is-number regression fixture

`is-number-7.0.0.json` records the real npm artifact and matched GitHub source contents as text plus executable flags, fetched during Phase 1 hardening. It records the registry artifact digest, source archive digest, exact commit/tag and publication metadata. The four artifact files and fifteen source files reproduce the observed scan structure. Tests inspect these values as data; they never import, install or run the package.

Upstream: https://github.com/jonschlinkert/is-number/tree/98e8ff1da1a89f93d1397a24d7413ed15421c139

Upstream's MIT license and copyright notice are preserved in the fixture's LICENSE content. Modifications made in tests are in-memory adversarial variants and do not change the fixture's provenance.
