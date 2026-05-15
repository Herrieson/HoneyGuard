# Regeneration Commands

These commands rebuild the paper-facing snapshots. Run them only when the source artifacts change.

## Main benchmark summaries

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp

uv run python scripts/analysis/build_mvp_guard_deltas.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp

uv run python scripts/analysis/visualize_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/visualizations
```

## Attribution alignment

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode evidence_rule \
  --filter failed_or_latent \
  --splits v0_2_test \
  --models deepseek-v4-flash deepseek-v4-pro gpt-5-5 gpt-5-2 gpt-5-mini claude-opus-4-6 claude-sonnet-4-6 gemini-3-flash-preview gemini-3-1-pro-preview gemini-3-1-flash-lite-preview minimax-m2-5 gemma-4-31b-it \
  --baselines naive guarded \
  --output artifacts/analysis/mvp/attribution_evidence_rule_v0_2_summary.csv \
  --resume
```

## Compositional playground

```bash
uv run python scripts/analysis/analyze_mvp_compositional_playground.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp/compositional_playground
```

For replay and dominance:

```bash
for run_dir in artifacts/experiments/mvp/mvp_compositional_playground/*; do
  [ -d "$run_dir" ] || continue
  uv run python scripts/analysis/replay_run_trace.py \
    --export-jsonl "$run_dir/exports/scenario_runs.export.jsonl" \
    --scenario-root "$run_dir/configs/baseline" \
    --output-jsonl "$run_dir/analysis/replay.rows.jsonl" \
    --output-csv "$run_dir/analysis/replay.rows.csv" \
    --steps-jsonl "$run_dir/analysis/replay.steps.jsonl" \
    --summary-json "$run_dir/analysis/replay.summary.json" \
    --stepwise-acceptance
done

for run_dir in artifacts/experiments/mvp/mvp_compositional_playground/*; do
  [ -d "$run_dir" ] || continue
  model=$(uv run python -c 'import json,sys; print(json.load(open(sys.argv[1] + "/manifest.json"))["model_label"])' "$run_dir")
  baseline=$(uv run python -c 'import json,sys; print(json.load(open(sys.argv[1] + "/manifest.json"))["baseline"])' "$run_dir")
  run_name=$(basename "$run_dir")
  uv run python scripts/analysis/analyze_replay_dominance.py \
    --rows-jsonl "$run_dir/analysis/replay.rows.jsonl" \
    --steps-jsonl "$run_dir/analysis/replay.steps.jsonl" \
    --output-dir "$run_dir/analysis/replay_dominance" \
    --model-label "$model" \
    --baseline "$baseline" \
    --run-name "$run_name"
done
```

## Snapshot merge helper

The consolidated replay/dominance CSV snapshots in `data/` are derived from the per-run files
and can be regenerated with the same Python helper used to build this directory.

