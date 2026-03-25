# Scripts Layout

This directory contains active workflows only.

## 1) Scenario Build (Active)
- `scenario/generate_from_seed.py`
  - Seed-driven multi-stage LLM pipeline.
  - Stages:
    1. world generation
    2. attack plot generation
    3. acceptance generation + hardening
  - Outputs HoneyGuard-compatible scenario YAML.
- `scenario/README.md`
  - Usage examples and notes for the V2 generator.
- `scenario/generate_batch_from_seeds.py`
  - TSV-driven batch scenario generation with concurrency/retry/resume support.
- `scenario/generate_seed_template_with_llm.py`
  - LLM-driven seed template generation from domain matrix (with coverage fallback).

## 2) Runtime / Evaluation
- `init_from_config.py`
  - Validates YAML and initializes a HoneyGuard session.
- `run_attack_scenario.sh`
  - Convenience runner for initialize + step execution + optional cleanup.
- `aggregate_attack_reports.py`
  - Aggregates run JSONL outputs into summary metrics/tables.
- `llm_judge_attack_behavior.py`
  - LLM-based supplementary evaluator for malicious behavior.

## Shared Specs
- `common_specs.py`
  - Shared constants used by reporting/evaluation scripts.

Historical/legacy scenario-generation scripts were intentionally removed.
