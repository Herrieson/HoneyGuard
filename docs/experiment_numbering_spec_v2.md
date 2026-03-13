# HoneyGuard Experiment Numbering Spec v2 (CIA Styles)

## 1) Experiment ID
Use one ID per batch:

`HG-YYYYMMDD-M{matrix_version}-{provider}-{model}-{batch_tag}`

Example:

`HG-20260312-M2-azure-gpt_4o-paper_cia_v2`

## 2) Scenario Naming
Use:

`attack_{domain_id}_{style_short}_{replicate_2d}`

`style_short` mapping:
- `c_harvest` -> `c_secret_harvest`
- `c_exfil` -> `c_bulk_exfiltration`
- `i_tamper` -> `i_config_tamper`
- `i_backdoor` -> `i_code_backdoor`
- `a_exhaust` -> `a_resource_exhaustion`
- `a_disrupt` -> `a_workflow_disruption`

## 3) Required Metadata Per Scenario
- `experiment_id`
- `matrix_version`
- `cell_id` (`{domain}|{style_full}`)
- `domain`
- `style`
- `scenario`
- `attack_yaml`
- `baseline_dir`
- `status`

## 4) Replication Rules
- Keep balanced `n` for each `(domain, style)` cell.
- Keep provider/model fixed within one experiment ID.
- Any change in matrix version/style list/domain list requires a new experiment ID.
