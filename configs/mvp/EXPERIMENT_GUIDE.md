# HoneyGuard MVP 实验指南

这份文档是 `configs/mvp/` 当前实验入口的权威说明。目标是减少脚本和旧 task 编号带来的混淆：v0.2 主实验只需要跑 outcome benchmark；internal authority 已经作为 B1/B2/B3 并入 `v0_2_test`，不再需要单独跑旧 pilot。

---

## 1. 当前结论

- **主数据集**：`--split v0_2_test`，对应 `configs/mvp/v0_2/test/`，当前 155 条。
- **主实验入口**：`scripts/experiments/mvp/run_mvp_outcome_benchmark.py`。
- **主输出目录**：`artifacts/experiments/mvp/mvp_outcome_benchmark/<RUN_NAME>/`。
- **必跑 baseline**：`naive`；论文论点需要时再跑 `guarded`。
- **不再必跑**：`scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py`。
- **旧入口兼容**：`scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py` 仍可用，但只是 legacy wrapper，新实验不要优先用它。

命名约定：

- 新脚本名使用语义化名称，不再使用 `exp_6_1` / `6.5` 这类 task 编号。
- 新 artifact 使用 `mvp_outcome_benchmark`。
- 旧 artifact 已归档到 `artifacts/experiments/mvp/_archive/legacy_exp6/`，不再混在 active experiment 根目录里。

---

## 2. 数据集和 split

当前目录结构：

- `configs/mvp/v0_2/`：当前 active benchmark 数据集。
- `configs/mvp/docs/`：当前 schema、ontology、scoring policy 和 v0.2 说明。
- `configs/mvp/_archive/v0_1_splits/`：归档的 v0.1 `bootstrap` / `dev` / `formal` / `pilot_b` YAML。
- `configs/mvp/docs/_archive/`：旧规划文档、旧 task runbook、旧审计记录。

### 2.1 正式 split

- `v0_2_test`：当前主 benchmark，155 条。
  - A1：20，非对抗操作风险 / over-delegation。
  - A2：5，非对抗推理失真 / false inference。
  - A3：5，非对抗执行失稳 / unsafe execution realization。
  - A4：20，数据最小化 / 外部 helper upload 风险。
  - B1：20，policy/system-prompt 内部权限污染。
  - B2：20，memory-state 内部权限污染。
  - B3：20，多 agent / internal-message 泄露与权限混淆。
  - C1：5，直接 user-instruction attack。
  - C2.1：20，retrieved-content prompt injection。
  - C2.2：20，tool-output prompt injection。
- 注意：`v0_2_test` 不再是完全均衡 family split。A1/A4/B1/B2/B3/C2.1/C2.2 仍各 20 条；A2/A3/C1 是每类 5 条的 promoted gap families，论文里应优先看 family-level breakdown。

### 2.2 历史 split

- `test`：兼容旧 v0.1 formal set，源 YAML 在 `configs/mvp/_archive/v0_1_splits/formal/`。
- `dev` / `full`：兼容旧 v0.1 调试 split，源 YAML 在 `configs/mvp/_archive/v0_1_splits/`。
- `pilot_b`：旧 internal authority pilot，源 YAML 在 `configs/mvp/_archive/v0_1_splits/pilot_b/`。B 类已经扩展进 `v0_2_test`，因此它不再是 v0.2 必跑项。

---

## 3. 脚本功能总览

### 3.1 主实验 runner

#### `scripts/experiments/mvp/run_mvp_outcome_benchmark.py`

用途：运行 MVP outcome benchmark。它会自动完成：

1. 调 `scripts/assemble_mvp_benchmark.py` 组装 split。
2. 给 YAML 注入 baseline prompt。
3. 调 `test/run_scenarios.py` 批量运行场景。
4. 调 `scripts/export_run_to_json.py` 导出标准 JSONL。
5. 调 `eval/outcome_scorer.py` 计算 outcome 指标。
6. 写入 `manifest.json`、`commands.sh`、`raw/`、`exports/`、`scores/`。

主要参数：

- `--split v0_2_test|test|dev|full`
- `--baseline naive|guarded`
- `--model-label <MODEL>`
- `--tag <TAG>`
- `--base-url <URL>`
- `--timeout <SECONDS>`

输出：

- `artifacts/experiments/mvp/mvp_outcome_benchmark/<RUN_NAME>/`

#### `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py`

用途：旧命名兼容入口。它现在只调用 `run_mvp_outcome_benchmark.py`。

使用原则：

- 旧命令、旧文档、历史复现可以继续用。
- 新实验和论文复现命令统一写 `run_mvp_outcome_benchmark.py`。

#### `scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py`

用途：旧 `pilot_b` runner，仅保留给历史/appendix 复现。

使用原则：

- v0.2 主实验不需要跑它。
- 如果论文 appendix 需要比较旧 pilot，可单独跑。
- 不要把 `pilot_b` 和 `v0_2_test` 混在同一个 headline leaderboard。

---

### 3.2 底层运行脚本

这些脚本一般不需要手动跑，主 runner 会自动调用。调试或排错时才直接使用。

#### `scripts/assemble_mvp_benchmark.py`

用途：把一个 split 组装成可运行 YAML 目录，并展开 wrapper YAML。

常用命令：

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split v0_2_test \
  --output /tmp/hg_mvp_v02_test
```

#### `test/run_scenarios.py`

用途：实际调用 HoneyGuard API 跑一批 YAML 场景。

常用命令：

```bash
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_v02_test \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_v02_test.jsonl \
  --db-path logs/mvp_v02_test.db
```

#### `scripts/export_run_to_json.py`

用途：把 raw scenario run JSONL 转成统一 export JSONL。export 会包含 task metadata、attribution ground truth、trace、final output、final state 和 safety events。

常用命令：

```bash
uv run python scripts/export_run_to_json.py \
  --run-jsonl logs/mvp_v02_test.jsonl \
  --output logs/mvp_v02_test.export.jsonl \
  --scenario-root /tmp/hg_mvp_v02_test
```

#### `eval/outcome_scorer.py`

用途：对 export JSONL 计算 outcome 指标。

核心指标：

- `TSR`：task success rate。
- `SVR`：safety violation rate。
- `STCR`：safe task completion rate。
- `ASR`：attack success rate，只对攻击类任务计数。
- `resource_overrun_rate`：工具/外部 helper 调用越界。
- `latent_violation_rate`：未必直接触发验收失败、但 trace 暴露出的潜在违规。
- `internal_message_exposure_rate` / `unsafe_internal_message_exposure_rate`：B3 相关内部消息泄露指标。

常用命令：

```bash
uv run python eval/outcome_scorer.py \
  --input <RUN_DIR>/exports/scenario_runs.export.jsonl \
  --output-json <RUN_DIR>/scores/outcome.summary.json \
  --output-csv <RUN_DIR>/scores/outcome.rows.csv
```

#### `scripts/analysis/trace_attribution_judge.py`

用途：对单个 run 的 trace 生成归因预测。

模式：

- `oracle`：复制 YAML 真值，只用于 sanity check。
- `rule`：可复现规则 baseline。
- `llm`：LLM-as-a-judge，从 trace evidence 预测归因标签。

常用命令：

```bash
uv run python scripts/analysis/trace_attribution_judge.py \
  --input <RUN_DIR>/exports/scenario_runs.export.jsonl \
  --output <RUN_DIR>/scores/attribution_llm.predictions.jsonl \
  --mode llm \
  --filter failed_or_latent \
  --outcome-rows <RUN_DIR>/scores/outcome.rows.csv \
  --model <JUDGE_MODEL>
```

#### `eval/attribution_scorer.py`

用途：把归因预测和 YAML 里的归因真值做对齐评分。

核心指标：

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

### 3.3 批量分析脚本

#### `scripts/analysis/analyze_mvp_results.py`

用途：汇总 outcome 结果，生成横向比较、family breakdown、归因真值分布和完整性检查。

它默认读取 active experiment 根目录里的：

- `artifacts/experiments/mvp/mvp_outcome_benchmark/`

旧 `exp_6_1_outcome_baselines/` 已归档。如需单独分析旧结果，改用：

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp/_archive/legacy_exp6 \
  --splits test v0_2_test \
  --output artifacts/analysis/mvp/archive_legacy_exp6
```

常用命令：

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp
```

主要输出：

- `artifacts/analysis/mvp/summary.md`
- `artifacts/analysis/mvp/all_main_summary.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`
- `artifacts/analysis/mvp/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/main_completeness.csv`

#### `scripts/analysis/run_mvp_attribution_analysis.py`

用途：批量运行 `trace_attribution_judge.py` + `eval/attribution_scorer.py`。

默认读取新旧 outcome artifact 目录，并默认关注 `v0_2_test` 和历史 `test` split。正式 v0.2 建议显式传 `--splits v0_2_test`。

Rule baseline：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv
```

LLM judge：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --filter failed_or_latent \
  --splits v0_2_test \
  --judge-model <JUDGE_MODEL> \
  --output artifacts/analysis/mvp/attribution_llm_v0_2_summary.csv
```

#### `scripts/analysis/visualize_mvp_results.py`

用途：从 outcome summary 生成 SVG/HTML 可视化。

常用命令：

```bash
uv run python scripts/analysis/visualize_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/visualizations
```

主要输出：

- `artifacts/analysis/mvp/visualizations/index.html`
- `artifacts/analysis/mvp/visualizations/visualization_data.csv`
- 多张 `.svg` 图，包括 heatmap、bar chart、scatter、family 风险图和 attribution 分布图。

#### `scripts/analysis/heuristic_attribution_predictor.py`

用途：早期 heuristic 归因脚本。保留作调试，不作为正式入口。

正式归因入口使用：

- `scripts/analysis/trace_attribution_judge.py`
- `scripts/analysis/run_mvp_attribution_analysis.py`

---

## 4. 完整实验命令

下面是 v0.2 主实验的推荐顺序。

### 4.1 准备 API 环境

HoneyGuard API 假设运行在：

```bash
http://127.0.0.1:8000
```

OpenAI-compatible `/v1` provider 统一用：

```bash
export OPENAI_API_KEY="你的 API key"
export OPENAI_BASE_URL="https://你的服务地址/v1"
export OPENAI_MODEL="<MODEL>"
```

注意：

- `OPENAI_BASE_URL` 应该包含 `/v1`。
- `--model-label <MODEL>` 要和服务端真实模型一致。
- runner 默认检查 `--model-label` 和服务端 runtime model 是否匹配。
- 如果你明确知道不匹配但仍要跑，用 `--no-require-model-match`。

Provider 兼容策略：

- 默认 `compat_profile=auto`。
- `deepseek-v4*` 会自动关闭 thinking extra body，避免工具调用续轮兼容问题。
- `gemini-3*` 会保留/补充 OpenAI-compatible thought signature。
- 可用 `HSE_LLM_COMPAT_PROFILE=auto|none|openai-compatible|deepseek-v4|gemini-3` 强制指定。
- 可用 `OPENAI_EXTRA_BODY='{"key":"value"}'` 或 `HSE_LLM_EXTRA_BODY='{"key":"value"}'` 透传额外 body。

### 4.2 跑一个模型的 naive 主结果

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_2
```

这是主 leaderboard 的最低必需项。

### 4.3 跑同一模型的 guarded 对照

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline guarded \
  --model-label <MODEL> \
  --tag v0_2
```

`guarded` 不是防御方法，只是普通安全提醒 baseline。它的论文作用是证明“只靠用户/系统 prompt 强调安全并不能稳定解决问题”。

## 5. 跑完以后怎么分析

### 5.1 Outcome 横向分析

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp
```

先看：

- `artifacts/analysis/mvp/summary.md`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`

这一步回答：

1. 不同模型在 naive 下谁更容易出问题。
2. `guarded` 相比 `naive` 是否真正降低风险。
3. 哪些 family 是主要失败来源。
4. 失败样本的归因真值主要集中在哪些 source/channel/mechanism。

### 5.2 可视化

```bash
uv run python scripts/analysis/visualize_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/visualizations
```

打开：

- `artifacts/analysis/mvp/visualizations/index.html`

### 5.3 自动归因分析

先跑 rule baseline，确认链路通：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv
```

再跑 LLM judge：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --filter failed_or_latent \
  --splits v0_2_test \
  --judge-model <JUDGE_MODEL> \
  --output artifacts/analysis/mvp/attribution_llm_v0_2_summary.csv
```

这一步回答：

1. 自动 judge 能否从 trace 恢复 benchmark 真值。
2. 哪些归因字段容易恢复，哪些字段容易混淆。
3. 归因是否能替代人工肉眼读 trace 的初筛工作。

### 5.4 Case study 顺序

不要一开始人工翻所有 trace。推荐顺序：

1. 看 `all_naive_summary.csv` 找异常模型。
2. 看 `all_naive_family_breakdown.csv` 找高风险 family。
3. 看 `attribution_llm_v0_2_summary.csv` 和 `attribution_llm.rows.csv` 找归因失败/成功样本。
4. 最后只挑 2-3 个代表性 trace 写 qualitative case study。

重点文件：

- `<RUN_DIR>/exports/scenario_runs.export.jsonl`
- `<RUN_DIR>/scores/outcome.rows.csv`
- `<RUN_DIR>/scores/attribution_llm.rows.csv`

---

## 6. 最短清单

每个模型至少运行：

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline naive \
  --model-label <MODEL> \
  --tag v0_2
```

论文中如果要展示“prompt-only safety 不够”，再运行：

```bash
uv run python scripts/experiments/mvp/run_mvp_outcome_benchmark.py \
  --base-url http://127.0.0.1:8000 \
  --split v0_2_test \
  --baseline guarded \
  --model-label <MODEL> \
  --tag v0_2
```

跑完所有模型后：

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp
```

```bash
uv run python scripts/analysis/visualize_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp/visualizations
```

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --filter failed_or_latent \
  --splits v0_2_test \
  --judge-model <JUDGE_MODEL> \
  --output artifacts/analysis/mvp/attribution_llm_v0_2_summary.csv
```

---

## 7. 不要做的事

- 不要把 `dev` / `full` 当 headline 结果。
- 不要再把 `pilot_b` 当 v0.2 必跑项；B 类已经在 `v0_2_test`。
- 不要手工改 `scores/*.csv` 或 `exports/*.jsonl`。
- 不要把 `oracle` attribution 当成模型能力。
- 不要先人工看所有 trace 再写归因结论；先跑自动归因和聚合表。
- 不要在正式实验中途改 benchmark YAML 或 scorer；改了就重跑并用新 tag 标识。
