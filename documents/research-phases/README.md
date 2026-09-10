# JSentinel phased work plan

Prepared September 10, 2026. Planning branch: `plan/research-phases`.

This folder replaces the earlier single implementation plan. Creating these guides does not start the scanner changes, regenerate the dataset, or revise the chapters. Each phase is a separate piece of work with its own stopping point.

## Start here

Read Phase 00 with Chris and the three groupmates before committing to a schedule. Assign owners based on actual availability. Start one implementation phase at a time and review its result before choosing the next phase.

| Phase | Deliverable | Depends on | Status |
| --- | --- | --- | --- |
| [00: Team and timeline](00-team-and-timeline.md) | Agreed workload, owners, and lab arrangements | None | Not started |
| [01: Browser scope and rule categories](01-browser-scope-and-categories.md) | Browser-only active checks in both scanners | 00 | Not started |
| [02: Validation handling](02-validation-handling.md) | Invalid checks cannot hide browser redirect findings | 01 | Not started |
| [03: Duplicate findings and scoring](03-findings-and-scoring.md) | One finding and one deduction for overlapping HTML checks | 02 | Not started |
| [04: Dataset and manifest](04-dataset-and-manifest.md) | Reviewed 54 vulnerable, 54 corrected, and 8 scenario files | 03; preparation can start after 01 | Not started |
| [05: Evaluator and freeze](05-evaluator-and-freeze.md) | Checked research evaluator and frozen test package | 04; evaluator prototype can use its pilot | Not started |
| [06: Survey tables and document setup](06-survey-and-document-setup.md) | Verified survey tables and professor-formatted draft shell | 00 | Not started |
| [07: AU lab testing](07-au-lab-testing.md) | Recorded results from actual lab PCs | 05 for measured runs; logistics can start after 00 | Not started |
| [08: Advisory guide and chapters](08-advisory-and-chapters.md) | Corrected guide and evidence-based Chapters I to V | 05, 06, and 07 for final results | Not started |

The technical sequence is 01 through 05, followed by measured lab runs in 07. Another groupmate can work on 06 while that sequence is underway. Phase 08 has separate batches for the advisory guide, targeted early-chapter corrections, Chapter IV, and Chapter V.

## Decisions carried forward

- Analyze browser-side source through both the web app and VS Code extension. Server-side scanning is outside the agreed scope.
- Keep the four identified problems in scope: false SSRF classifications, unreliable validation suppression, duplicate HTML findings and deductions, and incorrect A06 classifications.
- Keep 116 files: 108 controlled samples plus 8 simulated browser application scenarios. File count alone does not establish test quality.
- Treat accuracy measurement as a research procedure. No new accuracy dashboard or testing feature is required in the product.
- Use the professor's supplied Word templates. Preserve the user's existing Chapter III edits and make only the remaining evidence-based corrections.
- Keep survey perceptions, local development checks, and AU lab results separate. There is no target accuracy percentage to manufacture.

The expected scope after Phase 01 is 24 active base checks across 7 OWASP Top 10:2021 categories and 8 modules. Confirm the actual registry before using those counts in the paper. Check count is not a claim of complete category coverage.

## Working in small batches

A focused work block means roughly two hours of available work, not a delivery promise. The estimates in Phase 00 are discussion starters for the group. Each numbered batch in a phase can be completed and reviewed separately.

To resume, use a request such as: "Do Phase 02 from documents/research-phases/02-validation-handling.md and stop after its checks." For a larger phase, specify a batch. Completing one phase does not authorize running the rest automatically.

At each stop, record what changed, what was checked, unresolved issues, and the next dependency. Keep code and evidence versioned together when formal testing begins. The plan files are tracked; the existing research documents and respondent data remain ignored. References to those local source files will require access to the group's own copies.

These guides are working notes. Transfer only reviewed chapter content into the paper. Remove chat references, comment markers, prompts, and work checklists from chapter drafts.
