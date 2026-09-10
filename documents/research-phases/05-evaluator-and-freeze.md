# Phase 05: Build a small evaluator and freeze the test package

Status: Not started. Depends on Phase 04; a prototype can use its reviewed pilot. Suggested size: 2 to 4 focused blocks.

Accuracy measurement is a research procedure performed with a separate evaluator. It is not a proposed end-user feature. Keep the evaluator small: a manifest, adapters to the actual scanners or their recorded outputs, and checkable CSV or JSON results.

## Batch A: Verify the evaluator on the pilot

Use the same reviewed manifest for both scanners. Retain raw findings with rule ID, location, guidance ID, severity, and any parse or rule-execution errors. Reuse existing scan/export data where possible; do not create a second scanner inside the evaluator.

Check the evaluator with known missing, unrelated, duplicated, and correctly matched findings. Include parse failure and partial-scan examples. Its calculations must work even when the scanner is wrong.

## Batch B: Keep the measurements distinct

| Measurement | Counting rule |
| --- | --- |
| File-level confusion matrix | A fully scanned controlled file is positive when it has an in-scope vulnerability alert under the recorded alert policy. Compare with the reviewed file label. This broad measure does not establish detection of the intended rule. |
| Expected-rule detection | Match each expected vulnerability to an actual finding by rule ID and reviewed location, one to one. An unrelated alert cannot count as detecting the expected vulnerability. |
| Scenario observations | Report expected and actual findings, mismatches, completion, and timing separately for the eight scenarios. |
| Scan completion | Record attempted, completed, partial, and failed scans separately. Partial or failed scans are not clean negatives. |

State which advisory-only findings are excluded from vulnerability metrics and report them separately. Freeze that policy before the formal run. An unmatched alert requires review of the sample's ground truth; do not silently assume it is either correct or false.

For the controlled file-level matrix, calculate accuracy `(TP + TN) / N`, precision `TP / (TP + FP)`, recall or true positive rate `TP / (TP + FN)`, specificity `TN / (TN + FP)`, false positive rate `FP / (FP + TN)`, and false negative rate `FN / (FN + TP)`. Multiply by 100 for percentages. `N` is the number of completed eligible controlled scans. Show attempted counts and exclusions beside the metrics. A zero denominator is `N/A`.

Report expected-rule recall and finding-level precision separately, with their own counts and definitions. Never present a positive file caused by the wrong rule as successful target detection.

## Batch C: Freeze before formal measurement

Record the scanner build or commit, active rule list, dataset and manifest hashes, evaluator version, matching policy, and known limitations. Review labels before viewing formal results. Preserve old results if a later correction requires a new version and rerun.

The existing 108-file pass result is a development observation, not a preset result for the revised benchmark. Repeated deterministic output does not prove correct vulnerability classification. No accuracy target controls the labels or sample selection.

## Done and stop

- [ ] Known evaluator cases produce the correct matches, errors, and denominators.
- [ ] Both implementations have local results with raw evidence retained.
- [ ] No duplicate, unrelated alert, or failed scan can create a false target-detection pass.
- [ ] The research package is reproducible and its limitations are recorded.

Stop with a frozen package and local verification. Node-based engine checks do not establish web-browser or VS Code performance on AU PCs.
