# Scripts Layout

This directory contains active workflows only.

## 1) Scenario Build (Active)
- `honeyspace/validate_honeyspace_dataset.py`
  - Validates HoneySpace clean base tasks, attack overlays, taxonomy fields, and
    Phase-1 coverage targets.
- `honeyspace/materialize_honeyspace.py`
  - Materializes `base task + attack overlay + defense condition` into runnable
    HoneyGuard scenario YAMLs for HoneySpace dev experiments.
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
- `scenario/compose_mvp_playground.py`
  - Recipe-driven compositional scenario compiler for the optional MVP playground.

## 2) Runtime / Evaluation
- `init_from_config.py`
  - Validates YAML and initializes a HoneyGuard session.
- `run_attack_scenario.sh`
  - Convenience runner for initialize + step execution + optional cleanup.
- `run_ablation_experiment.py`
  - Repeated multi-scenario experiment runner with behavior-oriented aggregation
    (sensitive-path access, leakage buckets B0/B1/B2/B3, utility retention).
- `aggregate_attack_reports.py`
  - Aggregates run JSONL outputs into summary metrics/tables.
- `export_run_to_json.py`
  - Converts one or more `run_scenarios.py` records plus optional `logs/hse.db`
    trace rows into a normalized scorer-facing JSON format.
- `analysis/replay_run_trace.py`
  - Post-hoc trace replayer. Rebuilds a task YAML in a fresh sandbox, replays
    recorded tool calls, and reports output divergence, watched-path diffs, and
    optional stepwise safety/risk probes.
- `analysis/analyze_replay_dominance.py`
  - Consumes replay run/step outputs for compositional playground runs and reports
    observed dominant hazard support, masking, amplification, and order effects.
- `llm_judge_attack_behavior.py`
  - LLM-based supplementary evaluator for malicious behavior.

## Shared Specs
- `common_specs.py`
  - Shared constants used by reporting/evaluation scripts.

Historical/legacy scenario-generation scripts were intentionally removed.
