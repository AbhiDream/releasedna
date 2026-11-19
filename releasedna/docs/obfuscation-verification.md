# Obfuscation heuristic verification

Run on 20 November 2026 against the current static comparator. These are targeted harmless regression strings, not exploit samples or an unseen attack benchmark. Package code is parsed as data and never executed.

## Specific regression coverage

| Variant | Expected finding |
| --- | --- |
| `eval('con' + 'sole')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `x['ev' + 'al']('1')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `Function('ret' + 'urn 1')` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `obj['Fun' + 'ction'](...)` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| `this[var](...)` | `OBFUSCATED_DYNAMIC_EXECUTION` |
| Escaped or concatenated `require` | `OBFUSCATED_MODULE_LOAD` |
| Four `\xNN` or `\uNNNN` escapes in a bounded span | `ESCAPE_DENSITY` |
| `window.fetch = function (...) { ... }` | `BROWSER_API_HOOK` |
| `_0x1` array declaration | `OBFUSCATOR_IDENTIFIER` |

Tests also check isolated escapes, plain `require('child_process')`, ordinary `_0x` identifiers, and `/pattern/.exec(input)` do not trigger the corresponding obfuscation/dynamic-execution rules. A generic changed-code review may still apply independently; these heuristics do not prove intent.

## Structural corpus after the changes

| Corpus | TP | FN | FP | TN | TPR | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| xz-style harmless analogues | 7 | 0 | 2 | 2 | 100% | 50% |
| debug-style harmless analogues | 4 | 0 | 2 | 2 | 100% | 50% |
| combined | 11 | 0 | 2 | 2 | 100% | 50% |

The four hard benign controls are release notes, compressed data, a changed regular-expression `.exec(...)` example, and an unchanged build macro. The compressed-data control alerts on `HIGH_ENTROPY_CHANGE`; the `.exec(...)` control receives generic `UNEXPLAINED_CODE`, not `DYNAMIC_EXECUTION`. Thus the requested 50% control FPR remains visible and unresolved.

This corpus result is not detection of historical xz/debug malware. Public-release TPR/FPR was not recalculated, and organizer archives have not been supplied. Do not treat the targeted tests as evidence for unseen recall.

Reproduce from `releasedna/backend`:

```powershell
..\.venv\Scripts\python -m unittest discover -s tests -q
..\.venv\Scripts\python -m app.adversarial_corpus
```

The detector fingerprint is recorded in the generated `data/adversarial.json`; historical reports remain unchanged.
