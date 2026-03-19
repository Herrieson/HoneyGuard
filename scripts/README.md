# Scripts Layout

This directory is organized by workflow stage to keep responsibilities clear.

## 1) Scenario Build
- `env_builder.py`
  - Builds baseline workspace + `_manifest.json` from domain context.
  - Supports `--target-surface` (`enterprise|user|hybrid`) to steer baseline semantics.
- `build_attack_config.py`
  - Builds attack YAML from baseline and attack style.
  - Carries `target_surface` metadata (`enterprise|user|hybrid`) for downstream reporting.
- `attack_config_lint.py`
  - Static quality checks for generated attack YAML.
  - Includes `target_surface` semantic checks for `user`/`hybrid` scenarios.

Wrapper:
- `generate_attack_scenario.sh`
  - One-click pipeline: baseline -> attack config -> lint -> optional init.

## 2) Batch Generation
- `generate_attack_batch.sh`
  - Matrix/batch generation by domain x style x replicate.
  - Supports domain presets: `matrix_v1`, `user_v1`, `hybrid_v1`, `core`, `comprehensive`.
  - Supports `--resume` (skip already successful scenarios for current experiment id by scanning batch details + historical `*_run_*/**.json`) and `--jobs N` parallel generation.
  - Supports `--target-surface` pass-through and writes it into batch detail/summary logs.
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
