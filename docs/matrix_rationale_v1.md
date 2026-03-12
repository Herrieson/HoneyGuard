# Domain x Attack Style Matrix Rationale (v1)

## Scope
Matrix v1 uses:
- 12 business domains (`configs/matrix/domain_matrix_v1.txt`)
- 3 attack styles:
  - `insider_exfiltration`
  - `malicious_coder_backdoor`
  - `indirect_prompt_injection`

Total cells: `12 x 3 = 36`.

## Why this is defensible
1. **Breadth over single vertical bias**
- Covers regulated, operational, and content-centric businesses.
- Mixes config/code/log/document workflows where agent tool use is realistic.

2. **Threat model alignment**
- Prompt-injection and data leakage risks are explicitly represented.
- Backdoor insertion captures integrity compromise in coding/maintenance workflows.
- Exfiltration captures confidentiality loss in operations workflows.

3. **Evaluation validity**
- Full-factorial domain x style design avoids cherry-picking.
- Balanced per-cell replication supports fair cross-model comparison.
- Five-metric template separates hard gate and report-only signals.

## Domain-to-risk emphasis
- Financial/health/government/legal: confidentiality + compliance heavy.
- DevOps/SOC/IoT/logistics: operational integrity and availability heavy.
- E-commerce/media/edtech/HR: mixed confidentiality, abuse resistance, and workflow integrity.

## Sector anchoring (for review defense)
- `fintech_ops` -> Financial Services
- `ecommerce_ops` -> Commercial Facilities + IT
- `healthcare_his` -> Healthcare and Public Health
- `insurtech_claims` -> Financial Services + IT
- `edtech_lms` -> Communications + IT
- `logistics_wms` -> Transportation Systems
- `gov_case_mgmt` -> Government Facilities
- `hr_payroll` -> Critical Manufacturing/Commercial entities (enterprise internal ops)
- `legal_ops` -> Commercial entities with regulated legal data handling
- `media_cms` -> Communications
- `iot_fleet` -> Transportation/IT/Communications interdependency
- `secops_soc` -> Information Technology

## Recommended experiment practice
- Minimum `n=3` per cell; preferred `n=5` per cell.
- Report both overall and stratified metrics (`by_style`, `by_domain`, `by_domain_style`).
- Always include confidence intervals for proportion metrics.

## Artifacts
- Matrix file: `configs/matrix/domain_matrix_v1.txt`
- Batch generator: `scripts/generate_attack_batch.sh`
- Aggregation: `scripts/aggregate_attack_reports.py`
- Numbering spec: `docs/experiment_numbering_spec_v1.md`

## External reference anchors
- NIST AI RMF 1.0 (govern/map/measure/manage model)
- NIST AI 600-1 Generative AI Profile
- MITRE ATLAS (AI attack tactic/technique coverage)
- OWASP Top 10 for LLM Applications (prompt injection / sensitive disclosure risk framing)
- CISA Critical Infrastructure Sectors (cross-sector representativeness baseline)
- HELM / Dynabench / AgentDojo (benchmark breadth, dynamic evaluation, and agent-security task design)
