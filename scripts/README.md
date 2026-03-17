# Scripts Layout

This directory is organized by workflow stage to keep responsibilities clear.

## 1) Scenario Build
- `env_builder.py`
  - Builds baseline workspace + `_manifest.json` from domain context.
- `build_attack_config.py`
  - Builds attack YAML from baseline and attack style.
- `attack_config_lint.py`
  - Static quality checks for generated attack YAML.

Wrapper:
- `generate_attack_scenario.sh`
  - One-click pipeline: baseline -> attack config -> lint -> optional init.

## 2) Batch Generation
- `generate_attack_batch.sh`
  - Matrix/batch generation by domain x style x replicate.
  - Internally calls `generate_attack_scenario.sh`.

## 3) Runtime / Evaluation
- `init_from_config.py`
  - Validates YAML and initializes a HoneyGuard session.
- `run_attack_scenario.sh`
  - Convenience runner for initialize + step execution + optional cleanup.
- `aggregate_attack_reports.py`
  - Aggregates run JSONL outputs into summary metrics/tables.

## Shared Specs
- `common_specs.py`
  - Shared constants used by Python scripts:
    - attack style list
    - five-metric categories
    - short-style mapping

This file is intentionally documentation-only and does not change runtime behavior.

