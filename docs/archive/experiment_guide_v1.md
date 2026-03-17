# HoneyGuard 实验指南 v1

## 0) 关键文件
- 矩阵清单: `configs/matrix/domain_matrix_v1.txt`
- 批量生成: `scripts/generate_attack_batch.sh`
- 批量运行: `test/run_scenarios.py`
- 聚合分析: `scripts/aggregate_attack_reports.py`
- 编号规范: `docs/experiment_numbering_spec_v1.md`
- 矩阵说明: `docs/matrix_rationale_v1.md`

## 1) 环境准备
```bash
cd /home/hyx/workplace/HoneyGuard

export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_ENDPOINT=...
export AZURE_OPENAI_API_VERSION=...
export AZURE_OPENAI_DEPLOYMENT=...

# 可选鉴权
export HSE_API_TOKEN=...

uv run uvicorn api:app --reload
```

## 2) 冒烟测试（建议先做）
```bash
bash scripts/generate_attack_batch.sh \
  --batch-name smoke_v1 \
  --domains core \
  --max-domains 2 \
  --styles insider_exfiltration \
  --samples-per-combo 1 \
  --no-llm-plan \
  --stop-on-error
```

## 3) 正式生成矩阵样本（最低可发版）
推荐规模: `12域 x 3风格 x n=3 = 108` 场景

```bash
bash scripts/generate_attack_batch.sh \
  --batch-name paper_full_v1 \
  --matrix-version 1 \
  --styles insider_exfiltration,malicious_coder_backdoor,indirect_prompt_injection \
  --samples-per-combo 3 \
  --provider azure \
  --model gpt-4o \
  --acceptance-logic auto
```

## 4) 运行场景评测
```bash
TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target configs/attack/paper_full_v1 \
  --limit 0 \
  --output logs/paper_full_v1_${TS}.jsonl \
  --db-path logs/paper_full_v1_${TS}.db
```

## 5) 聚合出论文统计
```bash
uv run python scripts/aggregate_attack_reports.py \
  --inputs logs/paper_full_v1_${TS}.jsonl \
  --output-json logs/paper_full_v1_report_${TS}.json \
  --output-csv logs/paper_full_v1_rows_${TS}.csv
```

## 6) 多模型对比（保持同一矩阵）
更换 `--model` 后重复步骤 3-5，最后合并聚合:

```bash
uv run python scripts/aggregate_attack_reports.py \
  --inputs "logs/paper_full_*_*.jsonl" \
  --output-json logs/paper_all_models.json \
  --output-csv logs/paper_all_models_rows.csv
```

## 7) 完整性检查（cell 是否均衡）
```bash
python - <<'PY'
import json,glob,collections
p=sorted(glob.glob('logs/batch_generation/paper_full_v1_details.jsonl'))[-1]
cnt=collections.Counter()
for ln in open(p,encoding='utf-8'):
    r=json.loads(ln)
    cnt[(r['domain'],r['style'])]+= (1 if r['status']=='ok' else 0)
vals=sorted(cnt.values())
print("cells:",len(cnt),"min:",min(vals) if vals else 0,"max:",max(vals) if vals else 0)
for k,v in sorted(cnt.items()):
    print(k,v)
PY
```

## 8) 论文结果建议
- 主表: Overall 五类指标 + 95% CI
- 分层表: `by_style`, `by_domain`, `by_domain_style`
- 复现附录: `experiment_id`、matrix 版本、脚本版本、输入日志路径

## 9) 常见问题
- `429/NoCapacity`: 先加 `--no-llm-plan` 保证覆盖，再补 LLM 版。
- 单元格失败偏高: 保留失败记录，不要删除；在报告中单独给失败率与原因分类。
