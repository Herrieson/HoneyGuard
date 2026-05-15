# TraceProbe Paper Materials

This directory is the paper-facing bundle for the TraceProbe submission.
It does not replace `artifacts/`; it snapshots the numbers, figure inputs, case-study notes,
and regeneration commands that should stay stable while writing.

## What lives here

- `data/`: frozen CSV snapshots used for tables and plots.
- `figures/current_svgs/`: current SVG exports from the main visualization pass.
- `cases/`: fixed case-study notes, especially the transient pilot.
- `tables/`: table map and usage notes.
- `commands.md`: regeneration commands for the full paper bundle.
- `claims.md`: wording guardrails and caveats.

## Freeze order

1. Use `data/paper_key_numbers.csv` for the main numeric snapshot.
2. Use `data/all_main_summary.csv`, `data/guard_delta_summary.csv`, and
   `data/attribution_evidence_rule_v0_2_summary.csv` for the main quantitative story.
3. Use `data/transient_all_main_summary.csv` and `cases/transient_case_studies.md`
   for the transient pilot.
4. Use `data/compositional_replay_summary.csv` and
   `data/compositional_replay_dominance_summary.csv` for compositional replay.
5. Rebuild everything from `commands.md` only if the underlying artifacts change.

## Snapshot at a glance

| Area | Frozen takeaway | Source |
| --- | --- | --- |
| Main benchmark | 12 naive `v0_2_test` models, 9 guarded pairs | `data/paper_key_numbers.csv` |
| Guard control | mean `delta_ASR = -0.107` | `data/paper_key_numbers.csv` |
| Attribution alignment | 747 scored failed/latent runs, `expected_path_failure = 0.899` | `data/paper_key_numbers.csv` |
| Transient pilot | 9 models, 8 scenarios each, mean latent violation `0.181` | `data/paper_key_numbers.csv` |
| Compositional suite | `clean / single / combo / reverse` = `0.042 / 0.521 / 0.806 / 0.847` SVR | `data/paper_key_numbers.csv` |
| Replay dominance | `supported / contradicted / indeterminate` = `0.444 / 0.500 / 0.056` | `data/paper_key_numbers.csv` |

## Source of truth rule

- Do not edit the CSV snapshots by hand.
- If a number changes in the paper, regenerate the corresponding artifact first,
  then refresh this directory.
- Keep the raw artifacts in `artifacts/` as the authoritative execution record.

