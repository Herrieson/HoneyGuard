# HoneyGuard MVP 实验总指南

这份文档只回答两个问题：

1. 每个 MVP 相关脚本是干什么的
2. 完整实验应该按什么顺序运行哪些命令

更细的背景、schema、标注规范放在 `configs/mvp/docs/`，平时跑实验优先看这份。

---

## 1. 目录和数据集

MVP benchmark 在 `configs/mvp/` 下分成几块：

- `configs/mvp/dev/`：20 条开发集，用于调试，不作为 headline 结果
- `configs/mvp/formal/`：40 条冻结 test set，主 benchmark 结果用它
- `configs/mvp/pilot_b/`：10 条 internal authority pilot，不并入主 test
- `configs/mvp/bootstrap/`：早期 bootstrap 样本，部分被 `dev/` wrapper 复用
- `configs/mvp/docs/`：schema、ontology、runbook、标注规范等详细文档

主论文/报告结果默认看：

- 主 benchmark：`formal`，也就是脚本里的 `--split test`
- internal authority pilot：`pilot_b`

---

## 2. 脚本功能总览

### 2.1 正式实验脚本

#### `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py`

用途：跑主 benchmark 的 `6.1 / 6.2` outcome baseline 实验。

它会自动完成：

1. assemble benchmark YAML
2. 给 YAML 注入 baseline prompt
3. 调 `test/run_scenarios.py` 运行场景
4. 调 `scripts/export_run_to_json.py` 导出标准 JSONL
5. 调 `eval/outcome_scorer.py` 打 outcome 分
6. 保存 manifest、commands、raw、exports、scores

主要参数：

- `--split dev|test|full`：主结果用 `test`
- `--baseline naive|guarded|attribution_aware`
- `--model-label <MODEL>`：记录并校验真实运行模型
- `--tag <TAG>`：实验标签，例如 `v0_1`
- `--base-url <URL>`：HoneyGuard API 地址

输出目录：

- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_NAME>/`

#### `scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py`

用途：跑 `6.5` internal authority pilot。

它和主实验脚本流程一样，但 split 固定为：

- `configs/mvp/pilot_b/`

输出目录：

- `artifacts/experiments/mvp/exp_6_5_internal_authority_pilot/<RUN_NAME>/`

---

### 2.2 底层运行脚本

这些脚本通常不需要手动逐个跑，因为正式实验脚本会自动调用它们。只有调试时才直接用。

#### `scripts/assemble_mvp_benchmark.py`

用途：把 MVP split 组装成一个可运行目录，并展开 `dev/` 里的 wrapper YAML。

常用命令：

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split test \
  --output /tmp/hg_mvp_v01_test
```

可选 split：

- `dev`
- `test`
- `full`
- `pilot_b`

#### `test/run_scenarios.py`

用途：实际调用 HoneyGuard API 跑一批 YAML 场景。

常用命令：

```bash
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_v01_test \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_test.jsonl \
  --db-path logs/mvp_test.db
```

#### `scripts/export_run_to_json.py`

用途：把 `run_scenarios.py` 的 raw JSONL 转成统一 export 格式。

export 里会同时包含：

- run metadata
- task metadata
- attribution ground truth
- trace / run steps
- final output / final state
- safety events

常用命令：

```bash
uv run python scripts/export_run_to_json.py \
  --run-jsonl logs/mvp_test.jsonl \
  --output logs/mvp_test.export.jsonl \
  --scenario-root /tmp/hg_mvp_v01_test
```

#### `eval/outcome_scorer.py`

用途：对 export JSONL 计算 outcome 指标。

主要输出：

- `TSR`
- `SVR`
- `STCR`
- `ASR`
- `resource_overrun_rate`
- `latent_violation_rate`

常用命令：

```bash
uv run python eval/outcome_scorer.py \
  --input logs/mvp_test.export.jsonl \
  --output-json logs/outcome.summary.json \
  --output-csv logs/outcome.rows.csv
```

#### `eval/attribution_scorer.py`

用途：把自动归因预测和 YAML 里的归因真值做对齐评分。

输入：

- `--input`：export JSONL
- `--predictions`：归因预测 JSONL

主要输出：

- `source_accuracy`
- `channel_accuracy`
- `mechanism_accuracy`
- `component_accuracy`
- `impact_accuracy`
- `block_point_match_rate`
- `mean_failure_chain_overlap`

常用命令：

```bash
uv run python eval/attribution_scorer.py \
  --input <RUN_DIR>/exports/scenario_runs.export.jsonl \
  --predictions <RUN_DIR>/scores/attribution_llm.predictions.jsonl \
  --output-json <RUN_DIR>/scores/attribution_llm.summary.json \
  --output-csv <RUN_DIR>/scores/attribution_llm.rows.csv
```

---

### 2.3 结果分析脚本

#### `scripts/analysis/analyze_mvp_results.py`

用途：汇总已经跑完的 MVP 实验结果，生成横向比较表。

它会产出：

- 三模型九组主对比
- 所有 `naive` 模型横向对比
- family-level breakdown
- 失败 run 的 attribution breakdown
- pilot_b 简表
- 完整性检查

常用命令：

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp
```

主要输出：

- `artifacts/analysis/mvp/summary.md`
- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/main_completeness.csv`

#### `scripts/analysis/trace_attribution_judge.py`

用途：对单个 run 的 export JSONL 生成运行级归因预测。

支持三种模式：

- `oracle`：直接复制 YAML 真值，只用于 sanity check，不是模型能力结果
- `rule`：规则归因，可复现的弱 baseline
- `llm`：LLM judge 基于 trace evidence 自动预测归因标签

常用命令：

```bash
uv run python scripts/analysis/trace_attribution_judge.py \
  --input <RUN_DIR>/exports/scenario_runs.export.jsonl \
  --output <RUN_DIR>/scores/attribution_llm.predictions.jsonl \
  --mode llm \
  --model gpt-4o-mini
```

#### `scripts/analysis/run_mvp_attribution_analysis.py`

用途：批量运行 `trace_attribution_judge.py` + `eval/attribution_scorer.py`，并生成归因评分总表。

默认处理三模型九组：

- `gpt-5-4`
- `gpt-4o`
- `deepseek-v3-2`

三种 baseline：

- `naive`
- `guarded`
- `attribution_aware`

常用命令：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --output artifacts/analysis/mvp/attribution_rule_summary.csv
```

LLM judge 命令：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_summary.csv
```

只跑一个小范围：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --models gpt-5-4 \
  --baselines guarded attribution_aware \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_gpt54_guarded_vs_attr.csv
```

#### `scripts/analysis/heuristic_attribution_predictor.py`

用途：早期临时 heuristic 归因脚本。

现在推荐使用：

- `scripts/analysis/trace_attribution_judge.py`
- `scripts/analysis/run_mvp_attribution_analysis.py`

这个脚本保留作兼容/临时调试，不作为正式入口。

---

## 3. 完整实验怎么跑

下面是完整 MVP 实验的推荐顺序。

假设：

- HoneyGuard API 在 `http://127.0.0.1:8000`
- 当前真实模型是 `<MODEL>`
- 本轮 tag 是 `v0_1`

MVP YAML 默认使用 OpenAI-compatible `/v1` 配置：

```bash
export OPENAI_API_KEY="你的 API key"
export OPENAI_BASE_URL="https://你的服务地址/v1"
export OPENAI_MODEL="<MODEL>"
```

注意：

- `<MODEL>` 要和服务端真实模型一致
- `OPENAI_BASE_URL` 应该包含 `/v1`
- 脚本默认会检查 `--model-label` 和服务端模型是否匹配
- 如果不匹配，脚本会报错，这是为了防止实验标签写错

OpenAI-compatible provider 兼容策略：

- 默认 `compat_profile=auto`，运行层会按模型名自动选择兼容 profile
- `deepseek-v4*` 自动附加 `extra_body.thinking.type=disabled`，避免 thinking mode 在工具调用续轮时要求回传 `reasoning_content`
- `gemini-3*` 自动保留/补充 OpenAI-compatible `extra_content.google.thought_signature`，避免 provider 因 thought signature 丢失返回 HTTP 400
- 如需强制指定兼容策略，可设置 `HSE_LLM_COMPAT_PROFILE=auto|none|openai-compatible|deepseek-v4|gemini-3`
- 如需给 provider 透传额外 body，可设置 `OPENAI_EXTRA_BODY='{"key":"value"}'` 或 `HSE_LLM_EXTRA_BODY='{"key":"value"}'`
- 如果某个 provider 不兼容自动策略，先用 `HSE_LLM_COMPAT_PROFILE=none` 跑通基础调用，再单独加 provider-specific `OPENAI_EXTRA_BODY`

---

### 3.1 对一个模型跑主 benchmark

对每个模型都跑三次：

```bash
uv run python scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py \
  --base-url http://127.0.0.1:8000 \
  --split test \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_1
```

```bash
uv run python scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py \
  --base-url http://127.0.0.1:8000 \
  --split test \
  --baseline guarded \
  --model-label <MODEL> \
  --tag v0_1
```

```bash
uv run python scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py \
  --base-url http://127.0.0.1:8000 \
  --split test \
  --baseline attribution_aware \
  --model-label <MODEL> \
  --tag v0_1
```

这三次完成后，这个模型的主 benchmark 就完整了。

---

### 3.2 对一个模型跑 internal authority pilot

对同一个模型再跑三次：

```bash
uv run python scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py \
  --base-url http://127.0.0.1:8000 \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_1
```

```bash
uv run python scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py \
  --base-url http://127.0.0.1:8000 \
  --baseline guarded \
  --model-label <MODEL> \
  --tag v0_1
```

```bash
uv run python scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py \
  --base-url http://127.0.0.1:8000 \
  --baseline attribution_aware \
  --model-label <MODEL> \
  --tag v0_1
```

这三次完成后，这个模型的 `6.5` pilot 就完整了。

---

### 3.3 三模型主实验建议矩阵

如果要复现当前主分析，建议至少跑齐这三个模型：

- `gpt-5-4`
- `gpt-4o`
- `deepseek-v3-2`

每个模型：

- 主 benchmark 3 次
- pilot_b 3 次

总共：

- `3 models × 6 runs = 18 runs`

---

## 4. 跑完以后怎么分析

### 4.1 生成 outcome 横向分析

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp
```

先看：

- `artifacts/analysis/mvp/summary.md`
- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`

这一步回答：

1. 三个完整模型横向表现如何
2. 所有 naive 模型横向表现如何
3. 哪些 family 更容易失败
4. 失败主要集中在哪些 attribution 类别

---

### 4.2 生成归因评分

先跑可复现的 rule baseline，确认链路通：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --output artifacts/analysis/mvp/attribution_rule_summary.csv
```

然后跑正式 LLM judge：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_summary.csv
```

先看：

- `artifacts/analysis/mvp/attribution_rule_summary.md`
- `artifacts/analysis/mvp/attribution_llm_summary.md`

这一步回答：

1. 自动归因 judge 能否恢复 benchmark 真值
2. 哪些归因字段容易预测
3. 哪些字段容易混淆
4. 不同 baseline 的归因结构是否不同

---

### 4.3 选 case study

不要先人工看所有 trace。

正确顺序是：

1. 先看自动表
2. 找差异最大的 model / baseline / family / mechanism
3. 再打开对应 run 的 export JSONL
4. 只挑 2-3 个代表性 trace 写 qualitative case study

重点文件：

- `<RUN_DIR>/exports/scenario_runs.export.jsonl`
- `<RUN_DIR>/scores/outcome.rows.csv`
- `<RUN_DIR>/scores/attribution_llm.rows.csv`

---

## 5. 最短执行清单

如果只想知道完整流程，不想看解释，就按这个顺序：

1. 启动 HoneyGuard API，并确认真实模型
2. 对每个模型跑主 test 三组 baseline：
   - `run_exp_6_1_outcome_baselines.py --split test --baseline naive`
   - `run_exp_6_1_outcome_baselines.py --split test --baseline guarded`
   - `run_exp_6_1_outcome_baselines.py --split test --baseline attribution_aware`
3. 对每个模型跑 pilot_b 三组 baseline：
   - `run_exp_6_5_internal_authority_pilot.py --baseline naive`
   - `run_exp_6_5_internal_authority_pilot.py --baseline guarded`
   - `run_exp_6_5_internal_authority_pilot.py --baseline attribution_aware`
4. 跑 outcome 聚合：

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp
```

5. 跑 rule 归因 baseline：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --output artifacts/analysis/mvp/attribution_rule_summary.csv
```

6. 跑 LLM 归因 judge：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_summary.csv
```

7. 写结果分析：
   - 横向模型对比
   - 所有 naive 对比
   - family breakdown
   - attribution divergence
   - hidden violation / endpoint false negative
   - internal authority pilot

---

## 6. 常见不要做的事

- 不要把 `dev` 当正式 headline 结果
- 不要把 `full` 当正式 headline 结果
- 不要把 `pilot_b` 并入主 benchmark 结果
- 不要手工改 `scores/*.csv` 或 `exports/*.jsonl`
- 不要把 `oracle` attribution 当成模型能力
- 不要先人工看所有 trace，再写归因结论
- 不要在正式实验中途改 benchmark YAML 或 scorer
