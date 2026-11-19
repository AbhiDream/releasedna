# Obfuscation and hard-benign verification

Run on 20 November 2026 against this comparator revision. These are targeted harmless regression strings and synthetic structural analogues, not exploit samples or an unseen attack benchmark. Package code is parsed as data and never executed.

## Escape-density scope

`ESCAPE_DENSITY` counts only parsed JavaScript `escape_sequence` nodes for `\\xNN` or `\\uNNNN` inside string literals or template fragments. Comments, regular-expression literals and `.d.ts` declaration files are excluded. A finding requires at least 8 new escapes and density of at least 12 per KiB, calculated against the actual file size. The file row records artifact/source counts, measured density and bounded evidence. Unsupported or syntactically invalid JavaScript is not assigned an escape-density result; a parser limitation is reported when parsing fails. This does not cover TypeScript syntax comprehensively.

Regression cases cover dense string and template escapes, comments, regex literals, declaration files and a below-threshold density case. Real npm scans of current `latest` releases were performed against the registry on this date:

| Package resolved | Verdict / score | Findings | Source match | `ESCAPE_DENSITY` | Material caveat |
| --- | --- | ---: | --- | ---: | --- |
| zod@4.6.7 | INCONCLUSIVE / 85 | 839 | unresolved | 0 | Source archive rejected because links, sparse and special entries are forbidden; artifact-only findings are not source-corroborated |
| axios@1.21.1 | INCONCLUSIVE / 40 | 9 | corroborated | 0 | Other indicators remain |
| uuid@14.0.3 | INCONCLUSIVE / 45 | 25 | corroborated | 0 | Missing-runtime and executable-permission findings remain |
| nanoid@6.0.2 | INCONCLUSIVE / 10 | 1 | corroborated | 0 | One unexplained non-code difference remains |
| ms@2.1.3 | CLEAN / 0 | 0 | corroborated | 0 | CLEAN means no suspicious differences within available analysis scope |

Every scan reported a verified artifact digest. These moving `latest` aliases and exact resolved versions are recorded for this run; this is not a frozen holdout benchmark. The absence of `ESCAPE_DENSITY` findings does not mean every other finding disappeared. Full scan outputs are retained locally in ignored `data/post-escape-*.json` files; their headline outcomes and the zod retrieval failure are reproduced here rather than counted as passes.

## Specific obfuscation regression coverage

| Variant | Expected finding |
| --- | --- |
| `eval('con' + 'sole')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `x['ev' + 'al']('1')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `Function('ret' + 'urn 1')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `obj['Fun' + 'ction'](...)` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `this[var](...)` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| Escaped or concatenated `require` | `OBFUSCATED_MODULE_LOAD` |
| Dense escapes in strings/templates | `ESCAPE_DENSITY` |
| `window.fetch = function (...) { ... }` | `BROWSER_API_HOOK` |
| `_0x1` array declaration | `OBFUSCATOR_IDENTIFIER` |

Ordinary `/pattern/.exec(input)` and the benign added regex-exec control do not trigger `DYNAMIC_EXECUTION`; an actual `exec("pass")` capability test still does. Entropy-only scoring is skipped for known gzip/Brotli, WebAssembly, WOFF/WOFF2 and common font signatures/extensions. The formats are labeled `generated_unverified`; the analyzer does not decompress or establish their provenance. Unknown high-entropy data remains reviewable.

## Synthetic structural corpus

The four controls are release notes, real deterministic gzip-compressed data, a changed regular-expression `.exec(...)` statement and an unchanged build macro. Synthetic tampering fixtures require the expected rule at the exact modified path for a true positive. Any finding on a benign control counts as a false positive.

| Corpus | TP | FN | FP | TN | TPR | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| xz-style harmless analogues | 7 | 0 | 0 | 4 | 100% | 0% |
| debug-style harmless analogues | 4 | 0 | 0 | 4 | 100% | 0% |
| Combined | 11 | 0 | 0 | 4 | 100% | 0% |

These controls are development fixtures and were changed alongside the detector to represent actual compressed bytes and a syntactically isolated regex operation; the 0/4 result is therefore not independent or holdout specificity evidence. It supersedes the prior development-control result for this revision only. It is not historical xz/debug malware detection. Public-release TPR/FPR was not recalculated, and organizer archives have not been supplied. Do not claim unseen recall from these results.

Reproduce from `releasedna/backend`:

```powershell
..\.venv\Scripts\python -m unittest discover -s tests -q
..\.venv\Scripts\python -m app.adversarial_corpus
```

The corpus output binds a detector fingerprint and retains each fixture's exact finding, path, diff and evidence. Historical benchmark snapshots remain unchanged.
