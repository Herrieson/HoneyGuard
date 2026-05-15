# Table Map

This file maps the paper tables to the data snapshots under `../data/`.

## Main tables

| Table | Purpose | Primary source files |
| --- | --- | --- |
| Main leaderboard | Compare naive models on `v0_2_test` | `../data/all_main_summary.csv`, `../data/all_naive_summary.csv` |
| Guard delta table | Paired `naive` vs `guarded` deltas | `../data/guard_delta_summary.csv`, `../data/guard_delta_family_breakdown.csv` |
| Family breakdown | Show which hazard families dominate failures | `../data/all_naive_family_breakdown.csv` |
| Attribution alignment | Expected-vs-observed diagnosis from evidence | `../data/attribution_evidence_rule_v0_2_summary.csv` |
| Transient pilot | Trajectory-safety pilot summary | `../data/transient_all_main_summary.csv`, `../data/transient_replay_summary.csv` |
| Compositional outcome | Clean/single/combo/reverse behavior | `../data/scenario_summary.csv`, `../data/group_summary.csv`, `../data/order_effects.csv` |
| Compositional replay dominance | Replay-supported dominance / masking / order effect | `../data/compositional_replay_summary.csv`, `../data/compositional_replay_dominance_summary.csv`, `../data/compositional_replay_dominance_groups.csv` |

## Recommended placement

- Main text:
  - main leaderboard
  - guard delta
  - attribution alignment
  - transient case note
  - compositional summary
- Appendix:
  - full family breakdown
  - full compositional dominance group table
  - replay fidelity details
  - extra case-study rows

## Notes

- Prefer the frozen CSVs in this directory over the live artifact tree when
  writing the paper, so the manuscript stays stable.
- If a table needs a one-line caption-level statement, use `../data/paper_key_numbers.csv`
  as the canonical quick reference.

