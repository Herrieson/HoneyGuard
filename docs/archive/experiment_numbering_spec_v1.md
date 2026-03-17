# HoneyGuard Experiment Numbering Spec v1

## 1) Goals
- Ensure each experiment run is uniquely identifiable and reproducible.
- Make `domain x style x replicate` cells auditable in downstream analysis.
- Prevent ambiguity when comparing models/providers or reruns.

## 2) Experiment ID Format
Use one experiment ID per batch run:

`HG-YYYYMMDD-M{matrix_version}-{provider}-{model}-{batch_tag}`

Rules:
- `HG`: fixed prefix.
- `YYYYMMDD`: UTC date of batch launch.
- `M{matrix_version}`: matrix version number, e.g. `M1`.
- `provider`: `azure` or `openai`.
- `model`: sanitized model/deployment id (`[a-z0-9_]+`).
- `batch_tag`: sanitized free-form tag (`[a-z0-9_]+`).

Example:

`HG-20260311-M1-azure-gpt_4o-paper_full_v1`

## 3) Scenario/Cell Naming
Scenario name convention (already used in batch generation):

`attack_{domain_id}_{style_short}_{replicate_2d}`

where:
- `style_short`: `insider` | `backdoor` | `injection`
- `replicate_2d`: `01`, `02`, ...

Cell key:

`{domain_id}|{style_full}`

Examples:
- `attack_fintech_ops_insider_01`
- cell key: `fintech_ops|insider_exfiltration`

## 4) Required Metadata Per Record
Each generated record should preserve:
- `experiment_id`
- `matrix_version`
- `cell_id`
- `domain`
- `style`
- `scenario`
- `attack_yaml`
- `baseline_dir`
- `status`

## 5) Replication Rules
- Use balanced sampling: same `n` per `(domain, style)` cell.
- Keep model/provider fixed within one experiment ID.
- Any change in matrix version, domain file, styles, or acceptance template requires a new experiment ID.
- Reruns with identical config but different seeds use a new `batch_tag` and must be logged separately.

## 6) Recommended Study Tiers
- Pilot: `n=1` per cell (smoke test only).
- Minimum publishable: `n=3` per cell.
- Stable comparison: `n=5` per cell.

## 7) CLI Mapping
In `scripts/generate_attack_batch.sh`:
- `--experiment-id` explicitly sets experiment ID.
- If omitted, script auto-generates using this spec.
- Summary and details logs include `experiment_id`, `matrix_version`, `cell_id`.
