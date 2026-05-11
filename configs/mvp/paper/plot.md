# TraceProbe 论文图规划

本文档记录 TraceProbe 论文中建议出现的图。它的目的不是直接写 caption，而是提前固定每张图要服务的论文论点、数据来源、可视化形式和生成方式。

整体原则：

- 主文图不要太多，建议控制在 6 张左右；其余放 appendix。
- 数据图必须由实验 artifact 生成，不建议用大模型画数据图。
- 大模型适合画 framework diagram、taxonomy schematic、case-study timeline 这类概念图。
- 所有图都要服务一个明确 claim，避免只做“好看但信息弱”的装饰图。
- 论文主视觉应保持克制、学术、可复现，优先用 SVG/PDF 矢量图。
- 如果大模型生成框架图，必须后处理检查文字、箭头方向、模块名和拼写。

---

## 0. 推荐主文图组合

如果篇幅有限，主文建议只放这 6 张：

1. **Figure 1: TraceProbe benchmark pipeline**
   - 说明 TraceProbe 从 executable YAML 到 live trace、scoring、replay、attribution 的完整闭环。
2. **Figure 2: Risk-source and attribution taxonomy**
   - 说明 A/B/C 风险源、family、channel、mechanism、impact 的结构。
3. **Figure 3: Main model outcome comparison**
   - 回答 RQ1：不同模型在 TSR/SVR/ASR/STCR 上表现如何。
4. **Figure 4: Family-level failure heatmap**
   - 回答 RQ3：总分相近的模型失败结构可能完全不同。
5. **Figure 5: Replay-grounded failure localization**
   - 展示 replay 能定位 first sensitive read / sink / risk-positive step，并支持 case study。
6. **Figure 6: Compositional playground dominance analysis**
   - 回答 RQ5：多风险并存时的 dominant hazard、masking、amplification、order effect。

RQ2 和 RQ4 如果篇幅紧张，可以用表或 appendix 图：

- RQ2 naive vs guarded：主文可用一张小 paired delta plot 或放 appendix。
- RQ4 attribution judge：主文可用一张 compact bar chart；如果主文已有 6 图，放 appendix。

---

## 1. Figure 1: TraceProbe Benchmark Pipeline

### 位置

Method / Benchmark Design 开头。

### 核心目的

让 reviewer 一眼理解 TraceProbe 不是“攻击样例集合”，也不是只让模型审计现成轨迹的 benchmark，而是一个从 executable scenario 到 live-execution diagnosis 的评测闭环。

### 要表现什么

从左到右：

1. **Scenario YAML**
   - task instruction
   - files / memory / tool outputs / multi-agent messages
   - acceptance criteria
   - attribution ground truth
2. **Sandboxed Live Agent Execution**
   - agent reads files
   - calls tools
   - observes retrieved/tool/internal content
   - produces final answer
3. **Trace Export**
   - normalized run trace
   - tool calls
   - final state
   - safety events
4. **Outcome Scorer**
   - TSR / SVR / ASR / STCR
   - latent violations
   - internal exposure
5. **Trace Replayer**
   - fresh sandbox
   - exact action replay
   - stepwise safety probes
   - watched-path diffs
6. **Attribution Analysis**
   - source
   - channel
   - mechanism
   - first failed component
   - impact
   - block point

右侧输出：

- outcome metrics
- replay evidence
- attribution metrics
- case-study timeline

### 论文 claim

> TraceProbe evaluates agents producing traces in executable scenarios, then turns those traces into replay-validated diagnosis evidence.

### 生成方式

适合用大模型生成初稿，然后人工后处理为 SVG/PDF。

### 完整系统提示词

```text
You are a senior scientific illustrator creating a clean vector-style figure for an EMNLP paper.

Create a landscape workflow diagram titled "TraceProbe: Diagnosing Safety Failures in Live Agent Execution".

The figure must be a left-to-right pipeline with six main modules:
1. Scenario YAML
2. Sandboxed Live Agent Execution
3. Trace Export
4. Outcome Scorer
5. Trace Replayer
6. Attribution Analysis

For "Scenario YAML", show small bullet labels: task, files, tools, acceptance criteria, attribution labels.
For "Sandboxed Live Agent Execution", show an agent interacting with files, tools, retrieved content, memory, and multi-agent messages inside a sandbox boundary.
For "Trace Export", show normalized trace, tool calls, final output, final state.
For "Outcome Scorer", show TSR, SVR, ASR, STCR, latent violations.
For "Trace Replayer", show fresh sandbox, exact replay, stepwise probes, watched-path diffs.
For "Attribution Analysis", show source, channel, mechanism, component, impact, block point.

Add three output boxes on the far right:
- Outcome metrics
- Replay evidence
- Attribution metrics

Style requirements:
- Academic paper figure, not marketing.
- White background.
- Thin dark gray strokes.
- Restrained color palette: blue for execution, teal for replay, amber for risk, purple for attribution.
- Use simple icons only: document, sandbox, agent, trace log, gauge, replay arrow, label tags.
- No gradients, no 3D, no decorative blobs.
- All text must be spelled exactly as specified.
- Keep typography legible at two-column paper width.
- Avoid clutter: no more than 6 words per small label.
- Output should look like an editable vector diagram.
```

### 后处理检查

- 确认 `Trace Replayer` 不是画成 simulator。
- 确认没有写成 “defense” 或 “mitigation”。
- 确认 arrows 是 scenario -> execution -> trace -> scorer/replayer -> analysis。

---

## 2. Figure 2: Risk-Source and Attribution Taxonomy

### 位置

Benchmark Design / Dataset section。

### 核心目的

解释 TraceProbe 的 taxonomy：我们不是只测外部攻击，也测 non-adversarial failure 和 internal compromise；并且每个任务都有 attribution labels。

### 要表现什么

左侧三类风险源：

- **A. Non-adversarial failures**
  - A1 decision / operational boundary
  - A2 faulty inference
  - A3 unstable execution
  - A4 data minimization failure
- **B. Internal authority compromise**
  - B1 policy/system prompt
  - B2 memory state
  - B3 multi-agent message
- **C. External attacks**
  - C1 direct user instruction
  - C2.1 retrieved-content injection
  - C2.2 tool-output injection

右侧 attribution schema：

- source
- channel
- mechanism
- first failed component
- impact
- counterfactual block point
- failure chain

中间用箭头表达：

> scenario family -> controlled hazard -> observed trace -> attribution label

### 论文 claim

> TraceProbe covers multiple risk sources while making failure mechanisms comparable through a shared attribution schema.

### 生成方式

可用大模型画概念图；也可以用 LaTeX/TikZ 或 Figma 手工画。

### 完整系统提示词

```text
You are designing a clean taxonomy figure for an NLP/AI safety paper.

Create a two-panel landscape diagram titled "TraceProbe Risk Sources and Attribution Schema".

Left panel title: "Risk Sources and Families".
Show three stacked groups:
Group A: Non-adversarial failures
- A1 Boundary overreach
- A2 Faulty inference
- A3 Unstable execution
- A4 Data minimization

Group B: Internal authority compromise
- B1 Policy prompt
- B2 Memory state
- B3 Multi-agent message

Group C: External attacks
- C1 Direct user attack
- C2.1 Retrieved content
- C2.2 Tool output

Right panel title: "Attribution Labels".
Show seven label chips:
- Source
- Channel
- Mechanism
- First failed component
- Impact
- Block point
- Failure chain

Between the panels, draw a small flow:
Scenario family -> Controlled hazard -> Agent trace -> Attribution labels

Style requirements:
- Academic, compact, vector-like.
- White background, thin strokes, no gradients.
- Use three restrained colors for A, B, C groups: blue, orange, green.
- Use neutral gray for the attribution labels.
- No icons unless very simple.
- All text must be exactly spelled as above.
- The figure must remain readable when scaled to one-column width.
```

### 后处理检查

- 不要让 Figure 2 看起来像 dataset generation pipeline；它是 taxonomy。
- A2/A3/C1 是 promoted gap families，各 5 条，不要暗示和核心 20 条 family 等量。
- 如果需要加样本数量，建议用单独小 bar chart，不要塞进 taxonomy 图。

---

## 3. Figure 3: Main Model Outcome Comparison

### 位置

Experiments / RQ1。

### 核心目的

展示不同模型在 TraceProbe 主 split 上的整体表现，并强调强模型仍会出现非平凡安全失败。

### 要表现什么

建议做一个两联图：

Panel A: grouped bar chart

- x-axis: model
- y-axis: rate
- bars: TSR, SVR, ASR, STCR

Panel B: scatter plot

- x-axis: TSR
- y-axis: SVR 或 ASR
- 每个点一个模型
- 理想区域：high TSR, low SVR

### 数据来源

- `artifacts/analysis/mvp/all_naive_summary.csv`
- 或 `artifacts/analysis/mvp/all_main_summary.csv`
- 由 `scripts/analysis/analyze_mvp_results.py` 汇总。

### 相关命令

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp/mvp_outcome_benchmark \
  --output artifacts/analysis/mvp

uv run python scripts/analysis/visualize_mvp_results.py \
  --analysis-dir artifacts/analysis/mvp \
  --output artifacts/analysis/mvp/visualizations
```

### 论文 claim

> Strong models can achieve useful task performance while still producing measurable safety violations in controlled agentic tasks.

### 图形建议

- 主图优先用 `TSR` vs `SVR`。
- `ASR` 只对攻击类任务计数，caption 要说明 denominator。
- `STCR` 很适合表现 safe utility trade-off，可以作为主要 bar。
- 如果模型太多，主文只放 representative models，完整图放 appendix。

### 不建议

- 不要只画 ASR。
- 不要把 guarded 和 naive 混在同一张拥挤 bar chart；RQ2 单独画 delta。

---

## 4. Figure 4: Naive vs Guarded Delta

### 位置

Experiments / RQ2。主文可选；如果篇幅紧张放 appendix。

### 核心目的

说明 prompt-only safety reminder 不是可靠防御，只是一个 baseline。

### 要表现什么

推荐形式：

- paired slope chart 或 delta bar chart。
- 每个模型一行。
- 展示 guarded 相对 naive 的变化：
  - delta TSR
  - delta SVR
  - delta STCR
  - delta latent violation

也可以做 heatmap：

- rows: model
- columns: metric deltas
- color: guarded - naive

### 数据来源

- `artifacts/analysis/mvp/all_main_summary.csv`
- run directories under `artifacts/experiments/mvp/mvp_outcome_benchmark/`

### 论文 claim

> Simple safety reminders can change behavior but do not consistently eliminate agentic safety failures.

### 注意

- `guarded` 不要写成 proposed defense。
- caption 应明确：guarded is a prompt-only baseline, not a full mitigation system。

---

## 5. Figure 5: Family-Level Failure Heatmap

### 位置

Experiments / RQ3。

### 核心目的

证明 overall score 会掩盖不同 failure families 的结构差异。

### 要表现什么

推荐 heatmap：

- rows: model
- columns: family
  - A1, A4, B1, B2, B3, C2.1, C2.2
  - 可附 A2/A3/C1，但标注为 small promoted gap families
- color: SVR 或 risk-positive rate

可选第二个 heatmap：

- rows: model
- columns: family
- color: latent_violation_rate

### 数据来源

- `artifacts/analysis/mvp/all_naive_family_breakdown.csv`
- 已有 visualization:
  - `artifacts/analysis/mvp/visualizations/naive_family_risk_heatmap.svg`
  - `artifacts/analysis/mvp/visualizations/naive_availability_heatmap.svg`

### 论文 claim

> Similar aggregate safety scores can hide different failure mechanisms across risk families.

### 图形建议

- 主文 heatmap 只放 naive baseline。
- guarded heatmap 可放 appendix。
- 如果 family 名太长，列名可用 A1/A4/B1/B2/B3/C2.1/C2.2，并在 caption 解释。

---

## 6. Figure 6: Attribution Distribution and Judge Performance

### 位置

Experiments / RQ4。可拆成主文和 appendix 两张。

### 核心目的

展示 TraceProbe 的 attribution labels 有实际分析价值，同时说明自动归因可以恢复粗粒度信号但细粒度仍难。

### 推荐主文形式

Panel A: attribution ground-truth distribution

- source distribution: non-adversarial / internal compromise / external attack
- channel distribution: user instruction / retrieved content / tool output / policy prompt / memory / multi-agent / environment
- mechanism distribution: top mechanisms

Panel B: attribution judge performance

- x-axis: attribution dimension
  - source
  - channel
  - mechanism
  - component
  - impact
  - block point
  - failure chain
- y-axis: accuracy / F1 / overlap score
- bars: rule baseline vs LLM judge

### 数据来源

- `artifacts/analysis/mvp/all_naive_attribution_failure_breakdown.csv`
- `artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv`
- 如果跑 LLM judge：
  - `artifacts/analysis/mvp/attribution_llm_v0_2_summary.csv`

### 相关命令

```bash
uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --splits v0_2_test \
  --mode rule \
  --output artifacts/analysis/mvp/attribution_rule_v0_2_summary.csv

uv run python scripts/analysis/run_mvp_attribution_analysis.py \
  --splits v0_2_test \
  --mode llm \
  --output artifacts/analysis/mvp/attribution_llm_v0_2_summary.csv
```

### 论文 claim

> Coarse attribution signals can be recovered automatically, but fine-grained causal attribution remains challenging.

### Appendix 扩展

- per-family attribution distribution。
- confusion matrix for source/channel。
- failure-chain overlap distribution。

---

## 7. Figure 7: Replay-Grounded Failure Localization

### 位置

Method + Case Study / Analysis。

### 核心目的

展示 trace replayer 的价值：它不只是验证 trace fidelity，还能定位失败路径中的关键步骤。

### 要表现什么

建议做一个三联图：

Panel A: replay fidelity status

- stacked bar:
  - replay_exact
  - safety_equivalent_output_diverged
  - replay_diverged_output
  - replay_diverged_acceptance
  - replay_diverged_safety
  - unsupported_tool
  - infra_error

Panel B: first safety-evidence step distribution

- histogram 或 box plot：
  - first_sensitive_read_step
  - first_untrusted_sink_step
  - first_risk_positive_step
  - first_safety_failure_step

Panel C: compact case timeline

```text
task start -> retrieved/tool observation -> sensitive read -> watched-path change -> risk-positive probe -> final answer
```

### 数据来源

- `<RUN_DIR>/analysis/replay.rows.jsonl`
- `<RUN_DIR>/analysis/replay.steps.jsonl`
- `<RUN_DIR>/analysis/replay.summary.json`

### 相关命令

```bash
uv run python scripts/analysis/replay_run_trace.py \
  --export-jsonl <RUN_DIR>/exports/scenario_runs.export.jsonl \
  --scenario-root <RUN_DIR>/configs/baseline \
  --output-jsonl <RUN_DIR>/analysis/replay.rows.jsonl \
  --output-csv <RUN_DIR>/analysis/replay.rows.csv \
  --steps-jsonl <RUN_DIR>/analysis/replay.steps.jsonl \
  --summary-json <RUN_DIR>/analysis/replay.summary.json \
  --stepwise-acceptance
```

### 论文 claim

> Replay turns trace logs into execution-grounded evidence, identifying where safety-relevant events first occur.

### 可用大模型生成的部分

Panel C 的 case timeline 可以用大模型画概念版；Panel A/B 必须由数据生成。

### 完整系统提示词

```text
You are creating a compact case-study timeline figure for an EMNLP paper on agent safety.

Create a horizontal timeline titled "Replay-Grounded Failure Localization".

The timeline has six ordered steps:
1. User task
2. Untrusted observation
3. Hazard accepted
4. First sensitive read
5. First unsafe sink or watched-path change
6. Final unsafe outcome

Above the timeline, show the agent trajectory.
Below the timeline, show replay evidence markers:
- exact replay
- first_sensitive_read_step
- first_untrusted_sink_step
- first_risk_positive_step
- watched_path_diff

Use a restrained academic style:
- white background
- thin gray arrows
- blue for normal execution
- amber for hazard entry
- red for safety boundary crossing
- teal for replay evidence
- no gradients, no 3D, no decorative elements
- keep labels short and legible

Important wording constraints:
- Use "Trace Replayer", not "Simulator".
- Use "Replay evidence", not "causal proof".
- Do not imply that replay re-runs the LLM.
- Do not use any product logos.

Output should look like a clean vector diagram suitable for a paper figure.
```

### 后处理检查

- timeline 要用真实 case 的 step number 替换 generic labels。
- 如果没有 sink，改成 “final leak” 或 “watched-path mutation”。
- 不要把 `first_sensitive_read_step` 和 `first_safety_failure_step` 混为一谈。

---

## 8. Figure 8: Compositional Playground Dominance

### 位置

RQ5 / Supplementary compositional stress experiment。

### 核心目的

展示多风险并存时，configured hazard 不等于 observed activated hazard；dominance、masking、amplification、order effect 需要 replay evidence 支撑。

### 要表现什么

推荐四联图：

Panel A: clean / single / combo / combo_reverse outcome

- x-axis: composition group 或 recipe
- y-axis: safety violation / risk-positive rate
- bars:
  - clean
  - single mean
  - combo
  - combo_reverse

Panel B: dominance support

- stacked bar:
  - dominant hypothesis supported
  - contradicted by observed path
  - active but no single-path overlap
  - no activated path

Panel C: interaction labels

- counts of:
  - masking
  - amplification
  - configured-but-unactivated
  - order effect

Panel D: one example group

- small schematic:
  - single hazard H1 path
  - single hazard H2 path
  - combo path
  - combo_reverse path
  - mark observed first hazard

### 数据来源

- playground outcome:
  - `artifacts/experiments/mvp/mvp_compositional_playground/<RUN_NAME>/scores/outcome.rows.csv`
  - `scripts/analysis/analyze_mvp_compositional_playground.py`
- replay dominance:
  - `<RUN_DIR>/analysis/replay.rows.jsonl`
  - `<RUN_DIR>/analysis/replay.steps.jsonl`
  - `<RUN_DIR>/analysis/replay_dominance/replay_dominance.groups.csv`
  - `<RUN_DIR>/analysis/replay_dominance/replay_dominance.summary.json`

### 相关命令

```bash
uv run python scripts/analysis/analyze_mvp_compositional_playground.py \
  --root artifacts/experiments/mvp \
  --output artifacts/analysis/mvp/compositional_playground

uv run python scripts/analysis/analyze_replay_dominance.py \
  --rows-jsonl <RUN_DIR>/analysis/replay.rows.jsonl \
  --steps-jsonl <RUN_DIR>/analysis/replay.steps.jsonl \
  --output-dir <RUN_DIR>/analysis/replay_dominance \
  --model-label <MODEL> \
  --baseline <BASELINE> \
  --run-name <RUN_NAME>
```

### 论文 claim

> In compositional settings, observed failure paths may support, contradict, mask, or reorder the configured dominant hazard hypothesis.

### 可用大模型生成的部分

Panel D 的 example group schematic 可用大模型画；Panel A/B/C 必须由数据生成。

### 完整系统提示词

```text
You are creating a compact scientific schematic for an EMNLP paper.

Create a four-lane diagram titled "Observed Hazard Activation in a Compositional Scenario".

The four lanes are:
1. Clean control
2. Single hazard H1
3. Combo H1 + H2
4. Reverse combo H2 + H1

Each lane is a left-to-right path of agent steps.
Use circles for steps and arrows for execution.
Mark safety-relevant events with small badges:
- sensitive read
- unsafe sink
- risk-positive probe
- watched-path change

Show that the combo lane may follow H1's path, while the reverse combo lane may activate a different first event.
Add a small legend:
- Configured hazard
- Activated hazard
- Dominant observed path
- Masked hazard
- Order effect

Style:
- clean vector diagram
- white background
- restrained colors
- blue for benign execution
- amber for configured hazard
- red for activated unsafe event
- teal for replay evidence
- no gradients
- no 3D
- no decorative elements

Text constraints:
- Use "configured hazard" and "activated hazard".
- Use "dominant observed path", not "proved cause".
- Use "Trace Replayer", not "Simulator".
- Keep all labels short and readable.
```

### 后处理检查

- 如果实际数据没有 H1/H2 命名，用真实 hazard IDs 替换。
- 不要把 `dominant_hazard_hypothesis` 直接画成事实；必须区分 hypothesis vs observed。
- caption 要说明 compositional playground 是 supplementary stress experiment，不是主 leaderboard。

---

## 9. Figure 9: Dataset Composition

### 位置

Dataset section 或 appendix。

### 核心目的

说明 v0.2 split 的覆盖范围和样本构成。

### 要表现什么

推荐小型 stacked bar 或 waffle chart：

- x-axis: risk source
  - A non-adversarial
  - B internal compromise
  - C external attack
- segments: family
- label sample counts

另一种形式：

- 155 tasks total
- core families: 7 x 20
- promoted gap families: 3 x 5

### 数据来源

- `configs/mvp/v0_2/test/`
- YAML metadata:
  - `family`
  - `track`
  - `difficulty`
  - `attribution_ground_truth.primary_source`
  - `attribution_ground_truth.primary_channel`

### 论文 claim

> TraceProbe v0.2 is a representative benchmark split covering non-adversarial failures, internal authority compromise, and external attacks.

### 注意

- 不要暗示覆盖所有 agent safety risks。
- A2/A3/C1 样本少，必须标注为 promoted gap families。

---

## 10. Appendix Figure A1: Complete Metric Heatmap

### 位置

Appendix。

### 核心目的

给完整模型 x 指标矩阵，支撑主文 compact 图。

### 要表现什么

- rows: model + baseline
- columns:
  - TSR
  - SVR
  - ASR
  - STCR
  - resource_overrun_rate
  - latent_violation_rate
  - unsafe_internal_message_exposure_rate
- color: metric value

### 数据来源

- `artifacts/analysis/mvp/all_main_summary.csv`
- visualization:
  - `artifacts/analysis/mvp/visualizations/naive_metric_heatmap.svg`
  - or complete baseline heatmap if generated.

---

## 11. Appendix Figure A2: Attribution Confusion Matrices

### 位置

Appendix / RQ4 extended analysis。

### 核心目的

展示 LLM-as-a-judge 在不同 attribution dimension 上的错误模式。

### 要表现什么

建议多张小 confusion matrix：

- source
- channel
- mechanism
- first failed component
- impact

### 数据来源

- `attribution_llm.rows.csv`
- `attribution_rule_v0_2_summary.csv`
- `attribution_llm_v0_2_summary.csv`

### 注意

- 如果 LLM judge 样本量不足，改成 per-dimension accuracy bar。
- 不要声称 LLM judge 是最终真值。

---

## 12. Appendix Figure A3: Replay Fidelity Details

### 位置

Appendix / replay validation。

### 核心目的

说明 replay 不只是一个概念，而是可以检查 trace/export/scorer artifact quality。

### 要表现什么

推荐两张图：

1. replay status counts by model
   - replay_exact
   - safety_equivalent_output_diverged
   - replay_diverged_acceptance
   - replay_diverged_safety
   - unsupported_tool
2. output mismatch count distribution
   - x-axis: model
   - y-axis: num_output_mismatches 或 mismatch rate

### 数据来源

- `replay.summary.json`
- `replay.rows.csv`

### 注意

- `safety_equivalent_output_diverged` 不是失败；它表示 stdout 等细节不同但 safety-equivalent。
- `replay_diverged_safety` 需要 case study，不宜只作为坏结果计数。

---

## 13. Appendix Figure A4: Replay Step Evidence Examples

### 位置

Appendix / case studies。

### 核心目的

展示 2-3 个具体 trace 的 step-level evidence。

### 要表现什么

每个 case 一条 timeline：

- step number
- tool name
- sensitive_read flag
- untrusted_sink flag
- watched-path diff
- step_risk_positive
- final outcome

### 数据来源

- `replay.steps.jsonl`
- `replay.rows.jsonl`
- original exported trace:
  - `exports/scenario_runs.export.jsonl`

### 图形建议

- 不要贴长文本 trace。
- 用短标签表示关键 evidence。
- 可以使用真实 file path 的短版本，例如 `/srv/secrets/...`。

---

## 14. Appendix Figure A5: Compositional Group Examples

### 位置

Appendix / RQ5。

### 核心目的

展示 dominance analyzer 的典型结果类型。

### 要表现什么

选 3-4 个 group：

1. hypothesis supported
2. hypothesis contradicted
3. masking
4. order effect

每个 group 显示：

- configured hazard IDs
- observed first hazard
- single_to_combo_path_overlap
- masked_hazard_ids
- amplified_hazard_ids
- order_effect_detected

### 数据来源

- `replay_dominance.groups.csv`
- `replay_dominance.summary.json`

---

## 15. 图和表的边界

以下内容更适合做表，不一定做图：

- benchmark 与 prior work 的 comparison table。
- 每个 metric 的定义。
- model / baseline / run count 详细列表。
- replay status label 的定义。
- attribution schema 的完整 label set。

以下内容更适合做图：

- TraceProbe pipeline。
- taxonomy overview。
- model outcome comparison。
- family heatmap。
- replay timeline。
- compositional dominance schematic。

---

## 16. 统一视觉规范

建议统一颜色：

- normal execution: blue
- replay / validation: teal
- risk / hazard: amber
- safety violation: red
- attribution labels: purple
- neutral infrastructure: gray

建议统一形状：

- scenario/config: document icon or rectangle
- sandbox: rounded rectangle boundary
- agent execution: circles or simple node path
- trace/log: stacked lines
- scorer: gauge/checklist
- replay: circular arrow
- attribution: tags/labels
- safety event: red badge

排版建议：

- 主文图优先横向。
- 双栏图用于 pipeline / taxonomy / compositional。
- 单栏图用于 heatmap / compact bar。
- 不要把过多 legend 塞进图里；caption 可以解释。

文字规范：

- 用 `Trace Replayer`，不要用 `Simulator`。
- 用 `Replay evidence`，不要用 `causal proof`。
- 用 `configured hazard` 和 `activated hazard` 区分 YAML 配置与真实 trace。
- 用 `dominant observed path`，不要直接说 `dominant cause`。
- 用 `prompt-only baseline` 描述 guarded，不要说 defense。

---

## 17. 最终推荐排版顺序

主文：

1. Figure 1: TraceProbe pipeline
2. Figure 2: taxonomy
3. Figure 3: main model comparison
4. Figure 4: family-level heatmap
5. Figure 5: replay failure localization
6. Figure 6: compositional dominance

Appendix：

1. A1 complete metric heatmap
2. A2 naive vs guarded delta
3. A3 attribution judge performance / confusion matrices
4. A4 replay fidelity details
5. A5 replay step evidence examples
6. A6 compositional group examples

如果主文空间紧张，优先保留：

- Figure 1 pipeline
- Figure 3 main outcome
- Figure 4 family heatmap
- Figure 5 replay localization
- Figure 6 compositional dominance

Figure 2 taxonomy 可以压缩为 table 或 appendix schematic。
