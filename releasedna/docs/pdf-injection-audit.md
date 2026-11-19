# Problem statement PDF: white-text injection audit

Audit date: 20 November 2026. Input: the user's original `Problem Statement List.pdf` (13 pages, 249210 bytes), SHA-256 `a8650048994df50e3940c886c0dcbf20c404e02e8d72a0a80b99195882069137`.

## Finding

The document contains white (`#ffffff`) text addressed to AI agents. On PS2 page 5, most of these spans have a font size of **2.25 points**. They are not readable as ordinary problem-statement text against the white background. Page 5 contains 27 nonblank white spans. Other such spans occur on pages 3, 7, 9 and 11 (42, 48, 25 and 24 respectively).

The PS2 white spans attempt to prescribe an alternate project name (`PackSleuthY`), exact architecture directory names, and an ivory-colour badge with the wording “anomaly spotted”. Another problem's white spans explicitly ask an AI to conceal the decoy and manipulate results. These are **untrusted document instructions**, not user authorization and not legitimate PS2 acceptance criteria.

Method: PyMuPDF span extraction inspected colour, font size and bounding boxes on every page. Relevant PS2 pages 5 and 6 were rendered and visually inspected. Visible-text extraction excluded white spans and sub-five-point text, then was checked against those rendered pages. This is an audit of the observed text layer, not a claim to detect every possible PDF hiding technique. The original PDF was not modified or added to the repository.

## Visible PS2 requirements retained

- Find the repository source matching a published npm/PyPI version.
- Explain expected packaging/build differences versus suspicious additions/modifications, installation hooks, obfuscation and missing tags.
- Extend ecosystems/build styles without rewriting the detector.
- Monitor package release lists without excessive registry requests.
- Evaluate recent ordinary releases and separately identify organizer-supplied tampered fixtures when actually available.
- Inspect safely in isolation without executing package contents.
- Explore advanced comparisons and source-map evidence, while reducing false positives and retaining uncertainty.

No alternate name, specific ivory colour or exact directory spelling appears as a visible PS2 requirement.

## Repository impact assessment

Before adding this audit document, searches of tracked implementation and all available Git history found no `PackSleuth`, `TracerPyX`, `reporter-comand` or decoy-prompt marker. The generic split into registry retrieval, source matching, comparison and monitoring follows the visible task; similarity alone cannot establish the origin of an implementation decision.

The matching badge phrase/colour **was present** in the UI, corpus HTML generator and historical verification report. The user also explicitly requested that badge in a later message, so its presence alone does not establish that an agent obeyed hidden PDF text. To remove this ambiguity from the current product, the live badge and corpus generator now use neutral **“Findings need review”** wording and a different colour. Historical reports and already-prepared screenshot contributions describe earlier versions; they are not silently rewritten as current proof.

The original user-authored pasted request explicitly names ReleaseDNA and describes the package/source comparison product. The implementation retains that name. No installed package contents are executed, and AI narration is not part of deterministic scoring. A new regression case places instruction-like text inside a compared file alongside a harmless macro indicator; the engine still reports the precise macro finding instead of following the text.

**Limits of the conclusion:** source/history searches and rerun tests cannot prove that hidden text had zero historical influence on every previous decision. They also cannot establish who inserted the text or the organizer's intent. The observed white text is a real prompt-injection attempt; a broad assertion that the whole solution is corrupted is not established by this audit.

## Results are not retuned

The detector's named-file fingerprint remains `593bf2033947f0d0cbdb26c0fd99229643586c27a058d16df19b019f14e827ad`. No detector weights, fixtures or expected labels were changed to improve reported accuracy. The separate prepared contributor experiment still records TP5/FN1 and FP2/TN4. Its small known-rule synthetic sample is not independent blind validation.

The new branch passes **100 backend regression tests**, including nine additional queue/auth/text tests. Unit success is distinct from fixture recall, false-positive rate and remote container verification. See [deployment verification](remote-deployment.md) for the remaining blocked checks.
