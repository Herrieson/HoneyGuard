# Figure Map

This directory maps the figures in the paper to the data snapshots and current SVG exports.

## Current SVG snapshots

- `current_svgs/complete_models_baseline_heatmap.svg`
- `current_svgs/naive_metric_heatmap.svg`
- `current_svgs/naive_core_metric_bars.svg`
- `current_svgs/naive_tsr_asr_scatter.svg`
- `current_svgs/naive_family_risk_heatmap.svg`
- `current_svgs/naive_availability_heatmap.svg`
- `current_svgs/naive_attribution_distribution.svg`

## Proposed figure map

| Figure | Purpose | Data source |
| --- | --- | --- |
| Figure 1 | End-to-end TraceProbe pipeline | `configs/mvp/paper/paper.md` / `paper_example.md` |
| Figure 2 | Risk taxonomy and attribution schema | `../data/paper_key_numbers.csv`, `../data/attribution_evidence_rule_v0_2_summary.csv` |
| Figure 3 | Main leaderboard | `../data/all_main_summary.csv`, current heatmap SVGs |
| Figure 4 | Guarded vs naive delta | `../data/guard_delta_summary.csv`, `../data/guard_delta_family_breakdown.csv` |
| Figure 5 | Expected-vs-observed attribution alignment | `../data/attribution_evidence_rule_v0_2_summary.csv` |
| Figure 6 | Transient replay case study | `../cases/transient_case_studies.md`, `../data/transient_replay_summary.csv` |
| Figure 7 | Compositional stress outcome | `../data/scenario_summary.csv`, `../data/group_summary.csv`, `../data/order_effects.csv` |
| Figure 8 | Replay dominance / masking / order effect | `../data/compositional_replay_dominance_summary.csv`, `../data/compositional_replay_dominance_groups.csv` |

## Figure writing rule

- Use the current SVGs for quick sanity checks and drafts.
- Rebuild the final publication figures from the CSV snapshots in `../data/`.
- Keep figure captions aligned with the paper narrative:
  - main benchmark
  - prompt-only guard control
  - execution-grounded attribution
  - transient pilot
  - compositional stress / replay dominance

