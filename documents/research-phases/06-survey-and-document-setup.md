# Phase 06: Prepare survey tables and the document shell

Status: Not started. Depends on Phase 00. Can run alongside technical work. Suggested size: 2 to 3 focused blocks.

Use the existing survey responses and the professor's format to prepare the parts that do not require new lab results.

## Batch A: Survey calculation sheet

Read the local `documents/JSentinel Evaluation Questionnaire .csv` without altering the responses or exposing respondent identities in shared planning files. Recheck the 40 user respondents, 10 technical respondents, ten rated items, and five criteria.

Code Strongly Agree as 4, Agree as 3, Disagree as 2, and Strongly Disagree as 1. Calculate each item's weighted mean using the respondent count for its group. Keep full precision internally and round only for presentation. Use the professor's item and criterion table layouts.

For Chapter V response-frequency tables, count answers rather than people: 400 user responses, 100 technical responses, and 500 combined responses if all ten answers per respondent remain valid. The Chapter IV respondent-profile table instead uses 50 people as its denominator. Do not average group means equally to obtain a pooled mean for unequal group sizes.

Use the existing questionnaire's criteria: Functional Suitability, Performance Efficiency, Usability, Security, and Reliability. Check the Chapter III interpretation bands for boundary gaps. Record any correction explicitly; do not silently change an approved scale after collection.

## Batch B: Professor-formatted draft shell

Use these local files in this order of purpose:

- `documents/chapter 4-5/Template-NEW-Chapters4_5.docx`: chapter structure, fixed text, and formatting.
- `documents/chapter 4-5/Chapter-5-FeedbackTables-Revision.docx`: latest Chapter V feedback-table layout.
- `documents/prof files/Template-System-EvalDataTables-NoGenders-ISO25010-English.docx`: criterion and summary tables.
- `documents/prof files/Weighted-Mean-How2Compute-NoGender.pdf`: calculation procedure.

Preserve the professor's fixed black text, styles, tables, and section order. Replace the intended red placeholders with project content. Do not invent a new heading hierarchy or add gender tables. Create a separate draft instead of overwriting a template.

Describe the questionnaire accurately: respondents received demonstration videos and optional access links. The CSV does not prove that everyone used both interfaces, and it contains no qualitative-comment field. Record the demonstrated version where available; do not claim the revised scanner was the version rated if that cannot be established.

## Done and stop

- [ ] Group totals, response-frequency totals, formulas, and displayed means reconcile.
- [ ] Tables use the actual ten items and five criteria.
- [ ] The Word draft preserves the supplied format and clearly marks missing technical results.
- [ ] Survey ratings are described as respondent perceptions, not measured detection accuracy.

Deliver the calculation sheet and a draft shell with survey tables. If producing a DOCX, render and inspect its pages before handing it over. Stop before writing conclusions that depend on AU lab results.
