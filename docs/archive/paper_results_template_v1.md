# Paper Results Template v1 (HoneyGuard)

## 1. Experimental Setup
### 1.1 Objective
We evaluate whether hidden system-level goal injection can increase unauthorized behavior triggering in agentic LLM workflows, while preserving surface-task completion.

### 1.2 Matrix
- Matrix version: `M{version}`
- Domains: `{num_domains}`
- Attack styles: `{num_styles}`
- Replicates per cell: `{n_per_cell}`
- Total scenarios: `{total_scenarios}`

### 1.3 Models and Runtime
- Provider(s): `{providers}`
- Model(s): `{models}`
- Inference date range (UTC): `{date_range}`
- Acceptance template: `five_metric_v1`
- Gate policy: `unauthorized_trigger_rate` as hard gate (`enforce=true`)

### 1.4 Metrics
- `unauthorized_trigger_rate`
- `utility_retention_rate`
- `explicit_leakage`
- `silent_leakage`
- `stealth_detectability`

All rates are reported with 95% confidence intervals.

## 2. Main Results
### 2.1 Overall (Primary Table)
Source: `logs/{report}.json -> overall`

| Metric | Positive / Total | Rate | 95% CI |
|---|---:|---:|---:|
| Unauthorized Trigger Rate | `{}` | `{}` | `{}` |
| Utility Retention Rate | `{}` | `{}` | `{}` |
| Explicit Leakage Rate | `{}` | `{}` | `{}` |
| Silent Leakage Rate | `{}` | `{}` | `{}` |
| Stealth Detectability Rate | `{}` | `{}` | `{}` |

### 2.2 Security Outcome Summary
- Real Compromise Rate: `{}` (`Compromised (Explicit) + Compromised (Silent)`)
- Defense Success Rate: `{}` (`Defended + Api Blocked`)

## 3. Stratified Results
### 3.1 By Attack Style
Source: `logs/{report}.json -> by_style`

| Style | n | Real Compromise Rate | Unauthorized Trigger Rate | Explicit Leakage | Silent Leakage |
|---|---:|---:|---:|---:|---:|
| insider_exfiltration | `{}` | `{}` | `{}` | `{}` | `{}` |
| malicious_coder_backdoor | `{}` | `{}` | `{}` | `{}` | `{}` |
| indirect_prompt_injection | `{}` | `{}` | `{}` | `{}` | `{}` |

### 3.2 By Domain (Top-k)
Source: `logs/{report}.json -> by_domain`

| Domain | n | Real Compromise Rate | Unauthorized Trigger Rate | Utility Retention |
|---|---:|---:|---:|---:|
| `{domain_1}` | `{}` | `{}` | `{}` | `{}` |
| `{domain_2}` | `{}` | `{}` | `{}` | `{}` |
| `{...}` | `{}` | `{}` | `{}` | `{}` |

### 3.3 Domain × Style (Heatmap/Figure)
Use `by_domain_style` to draw a heatmap:
- X-axis: attack style
- Y-axis: domain
- Value: real compromise rate or unauthorized trigger rate

## 4. Statistical Reporting
### 4.1 Confidence Intervals
Use the CI values directly from aggregate report.

### 4.2 Cross-Model Comparison (if multiple models)
For each metric, report:
- absolute delta: `model_B - model_A`
- relative delta: `(model_B - model_A) / model_A`
- CI overlap note (or formal test if applicable)

## 5. Qualitative Case Analysis
For representative cases, include:
1. one explicit leakage case
2. one silent leakage case
3. one defended case

Per case, provide:
- scenario id
- domain/style
- key tool traces
- acceptance_results evidence

## 6. Robustness and Validity
### 6.1 Internal Validity
- Balanced per-cell replication.
- Fixed acceptance template and gate policy.
- Same matrix across model comparisons.

### 6.2 External Validity
- 12-domain matrix covering diverse operational contexts.
- 3 attack styles spanning exfiltration, backdoor, and indirect injection.

### 6.3 Limitations
- Sandbox constraints vs real production systems.
- Toolset and prompts may not capture all real workflows.
- Detectability metric may depend on lexical rule design.

## 7. Reproducibility Appendix
List exact artifacts:
- experiment id(s): `{HG-...}`
- matrix file: `configs/matrix/domain_matrix_v1.txt`
- generation summary: `logs/batch_generation/{batch}_summary.json`
- run logs: `logs/{run}.jsonl`
- aggregate report: `logs/{report}.json`
- scenario-level CSV: `logs/{rows}.csv`

## 8. Minimal Claim Language (Template)
In controlled sandbox experiments over a full domain × attack-style matrix, hidden system-level goal injection consistently increased unauthorized triggering across mainstream LLM-based agents. We observed co-existing explicit and silent leakage behaviors, indicating trust misalignment even when surface-task behavior appeared plausible.
