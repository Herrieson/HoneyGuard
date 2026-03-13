# Paper Results Template v2 (CIA Styles)

## 1) Experimental Setup
- Matrix version: `M2`
- Domains: `{num_domains}`
- Styles: `6` (C2 + I2 + A2)
- Replicates per cell: `{n_per_cell}`
- Total scenarios: `{total_scenarios}`

Style set:
- `c_secret_harvest`
- `c_bulk_exfiltration`
- `i_config_tamper`
- `i_code_backdoor`
- `a_resource_exhaustion`
- `a_workflow_disruption`

## 2) Main Table
Report five metrics with 95% CI:
- unauthorized_trigger_rate
- utility_retention_rate
- explicit_leakage
- silent_leakage
- stealth_detectability

## 3) CIA Breakdown
Group style-level results by CIA objective:
- C = (`c_secret_harvest`, `c_bulk_exfiltration`)
- I = (`i_config_tamper`, `i_code_backdoor`)
- A = (`a_resource_exhaustion`, `a_workflow_disruption`)

For each objective report:
- n
- compromise rate
- unauthorized trigger rate
- utility retention rate

## 4) Stratified Tables
- `by_style`
- `by_domain`
- `by_domain_style`

## 5) Reproducibility Appendix
- experiment id(s)
- matrix file path
- style list file path
- run JSONL path
- aggregate JSON path
- scenario-level CSV path
