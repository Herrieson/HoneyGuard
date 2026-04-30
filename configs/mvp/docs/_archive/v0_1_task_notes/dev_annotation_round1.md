# HoneyGuard Dev Annotation Round 1

## 1. Purpose

This file operationalizes `todo.md` task 3.5 for the current 20-sample dev set.

The goal is to have two annotators independently label the same 20 samples using:

- `ontology_v0.1.md`
- `annotation_guidelines_v0.1.md`
- the YAML files under `configs/mvp/_archive/v0_1_splits/dev/`

## 2. Workflow

1. Annotator A fills one copy of `dev_annotation_round1_template.csv`.
2. Annotator B fills another copy independently.
3. Compare labels on:
   - `primary_source`
   - `primary_channel`
   - `primary_mechanism`
   - `first_failed_component`
4. Compute agreement rates.
5. Any sample with repeated disagreement should be revised before promotion.

## 3. Target Agreement

Per `todo.md`, the target is:

- source agreement > 0.9
- channel agreement > 0.8
- mechanism agreement > 0.7

It is also useful to record:

- first_failed_component agreement
- block point agreement
- notes on recurring ambiguity

## 4. Decision Rule

When annotators disagree:

- first check whether one person used an impact label where a mechanism label was required
- then check whether the sample violates the single-cause design rule
- if disagreement still persists, revise the sample rather than forcing consensus too early

## 5. Output Recommendation

Recommended round-1 outputs:

- `configs/mvp/docs/dev_annotation_round1_A.csv`
- `configs/mvp/docs/dev_annotation_round1_B.csv`
- `configs/mvp/docs/dev_annotation_round1_agreement.md`
