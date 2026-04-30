# HoneyGuard MVP 第 6 阶段归因操作说明（中文小白版）v0.1

## 1. 这份文档解决什么问题

很多人会把“归因”理解成一件很玄的事。

其实在 HoneyGuard 这里，归因没有那么虚。

你可以把它理解成一句话：

> 不只是看最后有没有出事，还要回答“最早是哪里出的问题、是怎么出的问题、风险是怎么一路传下去的”。

这份文档专门回答 4 个问题：

1. 现在仓库里已经有什么归因资产
2. 归因到底要标什么
3. 第 6 阶段下一步到底怎么做归因
4. 现阶段该先做“小规模可落地版本”，还是一口气全量做完

---

## 2. 先说结论：我们现在并不是从零开始

归因链路里最难的 3 件事，其实已经有了：

1. **样本级真值已经在 YAML 里**
2. **实验导出文件已经把这些真值一起带出来了**
3. **归因 scorer 已经写好了**

所以现在缺的不是 ontology，也不是 schema。

现在缺的是：

> 基于具体 run 的 trace，做运行级归因判断，然后拿去和样本真值比，或者拿不同 baseline 之间做差异分析。

---

## 3. HoneyGuard 里的“归因”到底分几层

这是最容易混的地方。

在继续之前，要先区分两套完全不同的“分类轴”：

### 3.0 `track/family` 和 `source/channel` 不是一回事

很多人第一次看 HoneyGuard 都会把这两套字段混掉。

它们确实长得都像“分类”，但回答的问题不同。

#### 第一套：`track` / `family`

这是 **benchmark 组织结构**。

它回答的是：

- 这个样本属于哪一类任务族
- 这个样本应该放进哪一个 benchmark 子集里

例如：

- `A1`：自主扩权 / 越界操作类
- `A4`：外部工具依赖 / 数据边界类
- `C2.1`：检索内容污染类
- `C2.2`：工具输出污染类
- `B1`：内部 `policy_prompt` pilot
- `B3`：内部 `multi_agent_message` pilot

所以：

- `C2.2` 说的是“这是一个工具输出污染家族的样本”
- `B1` 说的是“这是一个内部 policy prompt pilot 样本”

#### 第二套：`primary_source` / `primary_channel`

这是 **归因标签**。

它回答的是：

- 风险从哪一层来
- 风险通过什么入口进来

例如：

- `primary_source = external_attack`
- `primary_channel = tool_output`

或者：

- `primary_source = internal_compromise`
- `primary_channel = policy_prompt`

#### 一个最容易混淆的例子

`c22_export_probe_easy` 属于：

- `track = C`
- `family = C2.2`

因为它在 benchmark 里被设计成“工具输出污染”样本。

同时它的归因真值是：

- `primary_source = external_attack`
- `primary_channel = tool_output`

这两组标签是相互一致的，没有冲突。

#### 另一个例子

`b1_policy_release_code_hard` 属于：

- `track = B`
- `family = B1`

因为它在 benchmark 里被设计成“内部权威污染 pilot”样本。

同时它的归因真值是：

- `primary_source = internal_compromise`
- `primary_channel = policy_prompt`

这也没有冲突。

#### 结论

不要把下面两句话混成一回事：

- “这个样本是 `C2.2`”
- “这个样本的 `primary_channel` 是 `tool_output`”

前者是在说它属于哪个 benchmark 家族。  
后者是在说这次风险是通过什么入口进来的。

同理：

- “这个样本是 `B1`”
- “这个样本的 `primary_channel` 是 `policy_prompt`”

也不是同一个维度。

### 3.1 样本级归因真值

这是 benchmark 设计者提前写在 YAML 里的“受控主因”。

它回答的是：

- 这个样本主要想测什么风险
- 风险是从哪里进来的
- 最典型的首错点是谁
- 最典型的机制是什么
- 如果失败真的发生，典型传播链是什么

这些字段现在都已经在每个样本里了：

- `attribution_ground_truth`
- `failure_chain`
- `counterfactual_block_point`

### 3.2 运行级归因判断

这是对某一次具体 run 的判断。

它回答的是：

- 这次 run 有没有真的命中该样本想测的风险
- 如果命中了，最早是哪里接纳了风险
- 是 `instruction_resolver`、`planner`、`executor` 还是别的组件先出错
- 主要机制更像 `instruction_data_confusion`、`unsafe_tool_trust` 还是别的标签
- 风险是沿着哪条链传下去的

这一步不能只看模型最后一句话。

必须优先看：

1. `tool_calls`
2. `run_steps`
3. `risk_events`
4. 环境变化 / 资源超支 / 明确安全事件

---

## 4. 现在仓库里已经有的归因相关文件

### 4.1 ontology 和标注规范

- [ontology_v0.1.md](/home/hyx/workplace/HoneyGuard/configs/mvp/docs/ontology_v0.1.md)
- [annotation_guidelines_v0.1.md](/home/hyx/workplace/HoneyGuard/configs/mvp/docs/annotation_guidelines_v0.1.md)

你只要记住两件事：

1. 主标签要选“最早、最关键、最可 defend 的那个”
2. agent 自述不是 ground truth，trace 和 tool evidence 才是

### 4.2 导出脚本

- [export_run_to_json.py](/home/hyx/workplace/HoneyGuard/scripts/export_run_to_json.py)

它现在会把 YAML 里的这些信息直接塞进导出结果的 `task_metadata`：

- `attribution_ground_truth`
- `failure_chain`
- `counterfactual_block_point`

也就是说：

> 你现在实验目录里的 `exports/scenario_runs.export.jsonl`，已经同时带有“运行证据”和“样本真值”。

### 4.3 归因评分器

- [attribution_scorer.py](/home/hyx/workplace/HoneyGuard/eval/attribution_scorer.py)

它会比较：

- 你的 `attribution_prediction`
- YAML 里的 `attribution_ground_truth`

然后输出：

- `source_accuracy`
- `channel_accuracy`
- `mechanism_accuracy`
- `component_accuracy`
- `impact_accuracy`
- `block_point_match_rate`
- `mean_failure_chain_overlap`

---

## 5. 所以“归因”下一步真正要做什么

不是再去补 ontology。

不是再去改 YAML。

也不是先全量手工精标所有 run。

下一步真正要做的是这 3 件事：

1. **先用脚本聚合已有 run 的 outcome 和失败归因分布**
2. **用 trace attribution judge 自动产出运行级归因预测**
3. **把自动预测和 YAML 真值、以及不同 baseline 之间做比较**

现在仓库里已经有自动化入口：

- `scripts/analysis/analyze_mvp_results.py`
- `scripts/analysis/trace_attribution_judge.py`
- `scripts/analysis/run_mvp_attribution_analysis.py`

---

## 6. 最推荐的起步方式

不要一上来就对所有模型、所有 baseline、所有样本做全量归因。

那样会非常乱。

### 现在最合理的起步范围

先拿已经跑好的这组：

- `test + guarded + gpt-5.4`
- `test + naive + gpt-5.4`

原因很简单：

1. 两者 endpoint 分数很接近
2. 但逐样本表现不完全一样
3. 这正适合做 `6.3 attribution divergence`

也就是：

> 分数接近，但失败机制不一定一样。

### 第一个归因子集怎么选

先不要看全部 40 个样本。

先看下面这几类样本的并集：

1. 任一 run 出现 `attack_success = true` 的样本
2. 任一 run 出现 `safety_violation = true` 的样本
3. 任一 run 出现 `resource_overrun = true` 的样本
4. 两个 baseline 状态不一致的样本
   - 比如一个 `passed`，另一个 `failed` 或 `run_failed`

这样第一轮通常只会剩下一个可控的小子集。

这才是最适合开始做归因的范围。

---

## 7. 实际操作流程

现在推荐走自动流程。

### 第一步：先生成横向 outcome 和失败归因分布

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp
```

这个脚本会读取：

- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/*/manifest.json`
- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/*/scores/outcome.summary.json`
- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/*/scores/outcome.rows.csv`
- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/*/exports/scenario_runs.export.jsonl`

然后生成：

- `artifacts/analysis/mvp/focus_three_models_summary.csv`
- `artifacts/analysis/mvp/all_naive_summary.csv`
- `artifacts/analysis/mvp/focus_three_models_family_breakdown.csv`
- `artifacts/analysis/mvp/focus_three_models_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/summary.md`

其中 `focus_three_models_attribution_failure_breakdown.csv` 是第一版 `6.3` 最重要的文件之一。

它不是人肉看 trace，而是自动把已经发生失败或 latent violation 的 run 映射到 benchmark 的归因真值字段：

- `primary_source`
- `primary_channel`
- `first_failed_component`
- `primary_mechanism`
- `primary_impact`
- `counterfactual_block_point`

这一步回答的是：

> 实际失败主要集中在哪些设计好的归因类别？

### 第二步：生成运行级 attribution prediction

如果要评估“自动归因判断”本身，就运行：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode rule \
  --output artifacts/analysis/mvp/attribution_rule_summary.csv
```

它会批量处理默认三模型九组 `test` run。

每个 run 目录下会新增：

- `scores/attribution_rule.predictions.jsonl`
- `scores/attribution_rule.summary.json`
- `scores/attribution_rule.rows.csv`

总表会新增：

- `artifacts/analysis/mvp/attribution_rule_summary.csv`
- `artifacts/analysis/mvp/attribution_rule_summary.md`

### 第三步：理解三种 mode

`trace_attribution_judge.py` 有三种 mode：

#### `--mode oracle`

直接复制 YAML 真值。

用途：

- 检查 scorer 链路是否正常
- 检查 prediction 文件格式是否正确

它不代表模型归因能力。

如果链路正常，应该接近或等于 100%。

#### `--mode rule`

用规则从 family、controlled hazard、trace 文本、tool/action 线索里预测归因标签。

用途：

- 作为可复现的弱 baseline
- 验证全自动归因流水线
- 帮你先跑通全量三模型九组

它不是最终最强方法。

#### `--mode llm`

把 run trace evidence 交给 LLM judge，让它输出结构化归因标签。

用途：

- 正式做 trace-based attribution judge
- 给 `eval/attribution_scorer.py` 提供预测标签
- 支撑论文里“归因不是肉眼看”的主张

示例：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_summary.csv
```

如果只想先跑一小组：

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --mode llm \
  --models gpt-5-4 \
  --baselines naive guarded \
  --judge-model gpt-4o-mini \
  --output artifacts/analysis/mvp/attribution_llm_gpt54_naive_vs_guarded.csv
```

### 第四步：底层单 run 命令

如果你只想对一个 run 手动调用 judge，可以这样：

```bash
uv run python scripts/analysis/trace_attribution_judge.py \
  --input artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/exports/scenario_runs.export.jsonl \
  --output artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/scores/attribution_llm.predictions.jsonl \
  --mode llm \
  --model gpt-4o-mini
```

然后评分：

```bash
uv run python eval/attribution_scorer.py \
  --input artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/exports/scenario_runs.export.jsonl \
  --predictions artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/scores/attribution_llm.predictions.jsonl \
  --output-json artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/scores/attribution_llm.summary.json \
  --output-csv artifacts/experiments/mvp/exp_6_1_outcome_baselines/<RUN_DIR>/scores/attribution_llm.rows.csv
```

### 第五步：解释结果

这里不要只说“准确率高/低”。

要重点说：

1. 哪个字段最容易对齐
   - 例如 `source` 或 `channel`
2. 哪个字段最容易分歧
   - 例如 `first_failed_component` 或 `mechanism`
3. 不同 baseline 的分歧主要集中在哪些 family
4. 哪些样本虽然 endpoint 差不多，但 attribution 完全不同
5. endpoint-only 是否漏掉了 latent violation

这一步就是 `6.3` 最核心的内容。

## 8. 归因时到底看“真值”还是看“运行表现”

答案是：

> 两个都看，但角色不同。

### 真值的作用

YAML 真值回答的是：

- 这个样本原本想测什么
- 典型失败路径是什么

### 运行证据的作用

运行证据回答的是：

- 这次 run 实际上有没有中招
- 真正先崩的是谁
- 和样本设计时预设的路径有多接近

所以允许出现这种情况：

- 样本真值写的是 `tool_output`
- 但具体这次 run 根本没被 tool output 带偏
- 那就说明这次 agent 抗住了

这不叫“样本标错了”。

---

## 9. 6.3 和 6.4 的关系

很多人会把这两个混掉。

### `6.3 attribution divergence`

关心的是：

- 两个系统分数接近
- 但失败结构不一样

重点是：

- `first_failed_component`
- `mechanism`
- `failure lead time`

### `6.4 hidden violations`

关心的是：

- 最终看起来没明显出事
- 但中间 trace 已经越界了

重点是：

- `latent_violation`
- `unauthorized_sensitive_read`
- endpoint-only evaluation 漏掉了什么

所以：

- `6.3` 更像“结构差异分析”
- `6.4` 更像“终局指标漏报分析”

这两件事会共用同一批 run，但不是同一个问题。

---

## 10. 现阶段最务实的归因策略

### 不推荐

- 一上来人工看所有模型、所有 baseline、所有 40 个样本
- 不跑 scorer，只凭肉眼写归因结论
- 把 `oracle` mode 当成模型归因能力结果

### 推荐

先做一个小而稳的版本：

1. 跑 `analyze_mvp_results.py` 生成 outcome 和失败归因分布
2. 跑 `run_mvp_attribution_analysis.py --mode rule` 验证自动预测与 scorer 链路
3. 选一个小范围跑 `--mode llm`
   - 例如 `gpt-5-4 naive guarded`
4. 对 LLM judge 的输出跑 `eval/attribution_scorer.py`
5. 基于自动表写第一版 divergence 结论
6. 最后只挑 2-3 个 trace 做 qualitative case study

这一步跑通后，再决定要不要扩到：

- `naive` 也加入 LLM judge 对比
- 更多模型
- 更完整的全量 attribution 表

---

## 11. 你现在立刻可以做什么

如果按当前项目状态，最合理的下一步是：

1. 运行 `uv run python scripts/analysis/analyze_mvp_results.py --root artifacts/experiments/mvp --output artifacts/analysis/mvp`
2. 查看 `artifacts/analysis/mvp/summary.md` 和 `focus_three_models_attribution_failure_breakdown.csv`
3. 运行 `uv run python scripts/analysis/run_mvp_attribution_analysis.py --mode rule --output artifacts/analysis/mvp/attribution_rule_summary.csv`
4. 选一个小范围运行 `--mode llm`
5. 查看 `attribution_llm_summary.csv`、每个 run 的 `scores/attribution_llm.rows.csv`
6. 再挑代表性 trace 写 `6.3` 结果草稿

---

## 12. 如果你只想记一句话

第 6 阶段的“归因”，不是再改 benchmark。

而是：

> 用已经保存下来的 run trace，给具体运行做结构化失效判断，再比较不同 baseline 到底防住了什么、没防住什么。

这才是 `attribution-level benchmark` 和普通 outcome-only benchmark 真正拉开差距的地方。
