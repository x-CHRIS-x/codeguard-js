# Phase 04: Improve the 116-file dataset

Status: Not started. Finalization depends on Phase 03; planning can begin after Phase 01. Suggested size: 3 to 5 focused blocks.

Keep 54 vulnerable samples, 54 corresponding corrected samples, and 8 simulated browser application scenarios. Review a small pilot before regenerating the full folder.

## Batch A: Six pairs and a manifest draft

Start with pairs covering browser redirects, exposed API keys, template HTML, function-result HTML, general HTML, and object merging. Vary actual code structure, input origin, or validation behavior. Changing comments or variable labels alone does not create meaningful additional coverage.

For each file, record a stable sample ID, pair or scenario ID, primary module, OWASP category, intended behavior, expected findings and locations, and the reason for each label. Record source references, necessary assumptions, reviewer, and whether the case was used during development. Use only synthetic credentials.

Separate vulnerability labels from expected scanner behavior. A filename or an existing scanner alert cannot establish ground truth. For an import or parsing operation, include the context that makes it unsafe. Record review-only expectations separately when the code does not establish a vulnerability.

## Batch B: Expand the controlled samples

The starting allocation is two distinct V/C pairs per active base check: 24 checks produce 48 pairs. Add the six priority pairs above to reach 54 pairs. Reconcile this allocation with the verified Phase 01 inventory before generating files.

Replace server-only samples with browser cases. Review clean counterparts for the intended weakness and unintended weaknesses. If a label remains ambiguous, resolve it before freezing the benchmark. Do not label a benign operation vulnerable simply to guarantee coverage or a passing score.

Update `test-samples/generate-samples.cjs` and `test-samples/samples/` together. Preserve a versioned copy or hashes of the prior dataset before replacement. The manifest must identify OWASP 2021 mappings without relying on the old filename prefixes.

## Batch C: Eight browser scenarios and the table inventory

Keep eight scenarios, adapting server-oriented examples into browser modules where necessary. Record multiple expected findings individually. Describe them as simulated workloads, not independently collected production applications. Keep them outside the controlled-sample confusion matrix.

Produce the paper's module counts from the manifest. Keep the existing table columns, a controlled subtotal of 108, a separate scenario row of 8 with dashes in the V/C columns, and a grand total of 116. Count each file once under its primary module or scenario group.

## Checks and stopping point

- [ ] Exactly 54 V files, 54 C files, and 8 scenario files exist.
- [ ] The generator reproduces the manifest and meaningful code variations.
- [ ] Every controlled pair has reviewed labels and expected locations.
- [ ] Uncertain advisory signals are not mislabeled as confirmed vulnerabilities.
- [ ] A groupmate reviews the labels where practical, with unresolved cases recorded honestly.
- [ ] Module-row totals reconcile with the subtotals and 116-file total.

Deliver the reviewed dataset, manifest, and table inventory. Stop before reporting accuracy or conducting formal lab runs.
