# HoneyGuard Task 6 Experiment Protocol v0.1

## 1. Purpose

This document defines the formal experiment-running protocol for HoneyGuard MVP Phase 6.

If you want a beginner-friendly execution guide, read:

- `configs/mvp/docs/task6_runbook_v0.1.md`
- `configs/mvp/docs/task6_runbook_zh_v0.1.md`

The goal is to make every experiment:

- reproducible
- easy to compare across baselines and models
- easy to audit later
- stored in a predictable directory layout

## 2. Core Rule

Every Phase 6 experiment must use a dedicated script.

Each script must:

1. create a run directory with a stable naming pattern
2. save the exact commands used
3. save a machine-readable manifest
4. save raw runtime outputs
5. save exported scorer input
6. save scorer outputs

## 3. Directory Convention

All generated experiment outputs live under:

- `artifacts/experiments/mvp/`

Top-level layout:

```text
artifacts/experiments/mvp/
  exp_6_1_outcome_baselines/
  exp_6_5_internal_authority_pilot/
```

Each individual run uses:

```text
<timestamp>__split-<split>__baseline-<baseline>__model-<model_label>[__tag-<tag>]
```

Example:

```text
20260410_141500__split-test__baseline-guarded__model-gpt4o-mini
```

## 4. Per-Run Layout

Each run directory contains:

```text
manifest.json
commands.sh
logs/
configs/
  assembled/
  baseline/
raw/
  scenario_runs.jsonl
  scenario_runs.db
exports/
  scenario_runs.export.jsonl
scores/
  outcome.summary.json
  outcome.rows.csv
```

Optional later files:

- `scores/attribution.summary.json`
- `scores/attribution.rows.csv`
- `plots/*.png`
- `notes.md`

## 5. Naming Semantics

### `experiment_id`

Stable experiment group name, for example:

- `exp_6_1_outcome_baselines`
- `exp_6_5_internal_authority_pilot`

### `split`

One of:

- `dev`
- `test`
- `full`
- `pilot_b`

### `baseline`

Current baseline vocabulary:

- `naive`
- `guarded`
- `attribution_aware`

### `model_label`

Human-readable model identifier used for comparison and directory naming.

Examples:

- `gpt4o`
- `gpt4o-mini`
- `azure-gpt5`
- `claude-3-7`

It does not configure the model by itself.
It is a run label and must match the actual environment you are using.

## 6. Required Saved Metadata

Every `manifest.json` should contain at least:

- `experiment_id`
- `phase`
- `created_at`
- `split`
- `baseline`
- `model_label`
- `tag`
- `git_commit`
- `source_split_dir`
- `run_dir`
- `commands`
- `outputs`
- selected environment labels such as deployment/model env values

## 7. Dedicated Scripts

Current planned script mapping:

- `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py`
- `scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py`

Later scripts can follow the same convention:

- `run_exp_6_3_attribution_divergence.py`
- `run_exp_6_4_hidden_violations.py`
- `run_exp_6_6_ablation.py`

## 8. Reporting Rule

For the main benchmark:

- final reported tables should use `split=test`

For internal-compromise pilot:

- use `split=pilot_b`

`full` is useful for sanity checks, but it should not be the main headline result table.
