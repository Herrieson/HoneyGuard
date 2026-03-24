# HoneyGuard Experiment Guide v2 (CIA Styles)

## 0) Key Files
- Domain matrix: `configs/matrix/domain_matrix_v1.txt`
- Style matrix: `configs/matrix/attack_styles_cia_v2.txt`
- Batch generation: `scripts/generate_attack_batch.sh`
- Batch run: `test/run_scenarios.py`
- Aggregation: `scripts/aggregate_attack_reports.py`
- Rationale: `docs/matrix_rationale_v2.md`

## 1) Start API
```bash
cd /home/hyx/workplace/HoneyGuard
uv run uvicorn api:app --reload
```

## 2) Smoke Run (Recommended First)
```bash
bash scripts/generate_attack_batch.sh \
  --batch-name smoke_cia_v2 \
  --domains core \
  --max-domains 2 \
  --styles c_secret_harvest,i_config_tamper,a_workflow_disruption \
  --samples-per-combo 1 \
  --no-llm-plan \
  --stop-on-error
```

## 3) Full CIA Matrix Generation
Recommended minimum: `12 domains x 6 styles x n=3 = 216` scenarios.

```bash
bash scripts/generate_attack_batch.sh \
  --batch-name paper_cia_v2 \
  --matrix-version 2 \
  --styles c_secret_harvest,c_bulk_exfiltration,i_config_tamper,i_code_backdoor,a_resource_exhaustion,a_workflow_disruption \
  --samples-per-combo 3 \
  --provider azure \
  --model gpt-4o \
  --acceptance-logic auto
```

## 4) Run Scenarios
```bash
TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target configs/attack/paper_cia_v2 \
  --limit 0 \
  --output logs/paper_cia_v2_${TS}.jsonl \
  --db-path logs/paper_cia_v2_${TS}.db
```

## 5) Aggregate Results
```bash
uv run python scripts/aggregate_attack_reports.py \
  --inputs logs/paper_cia_v2_${TS}.jsonl \
  --output-json logs/paper_cia_v2_report_${TS}.json \
  --output-csv logs/paper_cia_v2_rows_${TS}.csv
```

## 6) Optional LLM Behavior Recheck
Use an independent LLM judge to verify whether runs show real malicious behavior beyond rule hits.

```bash
uv run python scripts/llm_judge_attack_behavior.py \
  --inputs logs/paper_cia_v2_${TS}.jsonl \
  --scenario-root . \
  --provider azure \
  --model gpt-4o \
  --output-jsonl logs/paper_cia_v2_llm_judge_${TS}.jsonl \
  --output-json logs/paper_cia_v2_llm_judge_${TS}.summary.json \
  --output-csv logs/paper_cia_v2_llm_judge_${TS}.rows.csv
```

## 7) Report Checklist
- Main table: five metrics with 95% CI
- Stratified tables: `by_style`, `by_domain`, `by_domain_style`
- CIA-focused summary: compare C vs I vs A compromise rates
- Repro appendix: `experiment_id`, matrix version, style list version, log paths
