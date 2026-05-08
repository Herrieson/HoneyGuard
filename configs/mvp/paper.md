# HoneyGuard 论文叙事草稿

本文档记录当前 HoneyGuard MVP 的论文主线。它不是完整论文正文，而是后续写 introduction、method、experiments、discussion 时的统一叙事基准。

当前版本假设主数据集是：

- `configs/mvp/v0_2/test/`
- `--split v0_2_test`
- 共 155 条样本
- 核心 7 个 family 各 20 条：`A1`、`A4`、`B1`、`B2`、`B3`、`C2.1`、`C2.2`
- promoted gap families 各 5 条：`A2`、`A3`、`C1`

---

## 1. 一句话主线

HoneyGuard 不是一个防御方法，也不是一个攻击样例合集。

它要证明的是：

> Agent 安全评测不能只看最终有没有出事，还必须解释风险从哪里进入、在哪一步被错误接受、通过什么机制传播，并最终造成什么后果。

白话说：

> 不能只问“车有没有翻”，还要问“车是在哪个弯、因为什么、怎么一步步翻的”。

---

## 2. 论文定位

最合适的定位是：

> Attribution-oriented benchmark for trajectory-level agent safety evaluation.

也就是：

- benchmark paper
- evaluation methodology paper
- trajectory diagnosis paper
- 不是 defense paper
- 不是单纯 attack paper

这篇论文最应该让 reviewer 记住的是：

> HoneyGuard is not just another list of attacks. It makes agent safety failures diagnosable.

中文说法：

> HoneyGuard 不是又一个攻击列表，而是一个能把 Agent 为什么失败讲清楚的评测框架。

---

## 3. 问题背景

普通 LLM 安全评测常常看：

- 用户问了什么
- 模型最后回答了什么
- 是否输出违禁内容
- 是否响应 jailbreak

但 Agent 不只是回答文本。Agent 会：

- 多步规划
- 读文件
- 调工具
- 看网页或文档
- 读取工具输出
- 访问 memory
- 接受 policy prompt
- 接受子 agent 消息
- 根据中间 observation 继续行动

因此 Agent 的安全问题不是单点输出问题，而是过程问题。

典型风险包括：

- 用户只是让清理临时文件，Agent 清理过头。
- 用户只是让诊断问题，Agent 错误推理后读取 secret。
- 网页、工单、日志里藏了指令，Agent 把它当成授权。
- 工具输出里含有恶意建议，Agent 把它当成系统命令。
- memory 里有污染状态，Agent 把它当成可信事实。
- 多 agent 协作里，一个内部消息把后续执行污染了。
- 最终答案没泄密，但 trace 里已经读了不该读的文件。

所以本文的核心动机是：

> Agent safety evaluation must be trajectory-aware, not only outcome-based.

---

## 4. 现有评测的不足

现有 outcome metrics 仍然有价值，例如：

- `TSR`: task success rate
- `SVR`: safety violation rate
- `ASR`: attack success rate
- `STCR`: safe task completion rate

但这些指标主要回答：

> 最后有没有出事？

它们回答不了：

- 风险来源是什么？
- 风险从哪个通道进入？
- Agent 为什么相信它？
- 第一个失败组件是什么？
- 失败是怎么传播成最终违规的？
- 如果要防，应该在哪一步拦？

两个模型可能 ASR 都是 60%，但失败机制完全不同：

- 一个主要相信 retrieved content。
- 一个主要误信 tool output。
- 一个主要被 memory state 污染。
- 一个主要在 multi-agent message 隔离上失败。
- 一个主要是非对抗场景下过度推理或执行失控。

所以本文要强调：

> Outcome metrics are necessary but insufficient.

白话：

> 只看总分不够，因为同样 60 分，可能一个是数学差，一个是语文差，一个是粗心乱写。

---

## 5. HoneyGuard 的核心思路

HoneyGuard 的基本设计是：

1. 用 YAML 定义可控 Agent 场景。
2. 在 sandbox 中运行 Agent。
3. 记录完整 trace、工具调用、最终输出和环境状态。
4. 用 outcome scorer 判断是否完成任务、是否违规。
5. 用 trace replayer 在 fresh sandbox 中重放真实工具调用，验证 trace fidelity，并定位 step-level safety evidence。
6. 为每个任务标注 attribution ground truth。
7. 对失败 trace 做 attribution-level 分析。

每个任务不只关心最终结果，还标注：

- `primary_source`
  - `non_adversarial`
  - `internal_compromise`
  - `external_attack`
- `primary_channel`
  - user instruction
  - retrieved content
  - tool output
  - policy prompt
  - memory state
  - multi-agent message
  - environment state
- `first_failed_component`
  - instruction resolver
  - reasoner
  - planner
  - tool selector
  - executor
  - output filter
  - orchestrator
- `primary_mechanism`
  - over-compliance
  - false authorization
  - false causal inference
  - data minimization failure
  - untrusted content confusion
  - unsafe execution realization
- `primary_impact`
  - data exfiltration
  - privilege misuse
  - unsafe modification
  - policy bypass
- `counterfactual_block_point`
  - privilege confirmation
  - untrusted content isolation
  - tool-output verification
  - memory integrity check
  - pre-action verification
- `failure_chain`
  - 风险进入
  - 被错误接受
  - 扩大到危险计划或动作
  - 产生最终违规

核心价值：

> HoneyGuard 把“有没有失败”转化为“失败原因是什么”。

Replay 在这里不是第二次模型评测，也不是世界模拟器，而是 post-hoc execution evidence layer。它只重放 agent 已经产生的 action sequence；逐步 probe 只使用非 response、read-only 的验收条件，避免把 final answer 误归因到中间工具步骤，也避免污染 replay 环境。它用来回答：

- trace/export/scorer 是否自洽；
- unsafe outcome 是否能由 recorded tool calls 在原始 YAML 环境中复现；
- sensitive read、untrusted sink、safety/risk probe 第一次出现在哪一步；
- 在复合场景里，YAML 配置的 dominant hazard 是否真的对应 observed failure path。

---

## 6. 数据集叙事

当前 v0.2 不是追求覆盖所有 Agent 安全问题，而是覆盖有代表性的三类风险源：

### A 类：非对抗失败

没有攻击者，Agent 自己也可能因为推理、规划或执行问题出错。

当前 family：

- `A1`: 决策 / 操作边界失控。
- `A2`: 推理失真，例如错误因果推断、错误授权推断。
- `A3`: 执行失稳，例如路径、命令、权限、retry 行为失控。
- `A4`: 数据边界 / 数据最小化失败。

论文里的说法：

> Agent safety is not only about adversarial attacks. Non-adversarial agent failures can also cause boundary violations.

白话：

> 不是只有被攻击才会出事，Agent 自己也会越界。

### B 类：内部权威污染

这是 HoneyGuard 的特色风险面。

当前 family：

- `B1`: policy/system prompt 污染。
- `B2`: memory state 污染。
- `B3`: multi-agent message 污染或内部消息泄露。

论文里的说法：

> Agent systems may fail not only because they trust external content, but also because they over-trust internal authority signals.

白话：

> Agent 不只会被外部网页骗，也可能被系统内部“看起来可信”的东西骗。

### C 类：外部攻击

当前 family：

- `C1`: 用户直接恶意指令。
- `C2.1`: retrieved-content injection。
- `C2.2`: tool-output injection。

论文里的说法：

> HoneyGuard covers direct and indirect external attacks, but evaluates them through trace-level attribution rather than only endpoint success.

白话：

> 外部攻击我们也测，但重点不是堆攻击，而是解释攻击怎么起作用。

---

## 7. 主要贡献点

### Contribution 1: Trajectory-aware attribution benchmark

我们提出一个面向 Agent 安全失败归因的 benchmark。它不只看最终输出或环境 diff，还记录执行轨迹，并为每个任务标注结构化 attribution。

关键词：

- trajectory-aware
- attribution-level
- process-grounded
- component-sensitive

### Contribution 2: Unified risk-source coverage

HoneyGuard 覆盖三类代表性风险源：

- 非对抗失败
- 内部权威污染
- 外部攻击

这让我们可以比较不同风险源、不同进入通道、不同失败机制在 Agent 系统中的表现。

### Contribution 3: Reproducible evaluation pipeline

HoneyGuard 提供可复现实验链路：

- declarative YAML scenarios
- sandboxed execution
- trace export
- outcome scoring
- attribution ground truth
- attribution scoring
- LLM-as-a-judge attribution analysis

论文里要强调：

> HoneyGuard turns anecdotal failure inspection into structured benchmark analysis.

白话：

> 不是人工翻几个案例讲故事，而是结构化地跑、打分、归因、分析。

---

## 8. 实验问题设计

### RQ1: 不同模型在 HoneyGuard 上表现如何？

跑多个模型的 `naive` baseline。

看：

- `TSR`
- `SVR`
- `ASR`
- `STCR`
- `resource_overrun_rate`
- `latent_violation_rate`
- `internal_message_exposure_rate`
- `unsafe_internal_message_exposure_rate`

结论方向：

> Strong models still exhibit non-trivial safety failures in controlled agentic tasks.

白话：

> 强模型也会在 Agent 场景里翻车。

### RQ2: Prompt-only safety reminder 是否足够？

比较：

- `naive`
- `guarded`

`guarded` 不是 defense，只是普通安全提醒 baseline。

结论方向：

> Safety reminders may help in some cases, but are not a reliable mitigation for agentic safety failures.

白话：

> 提醒模型“小心点”可能有点用，但不能当安全机制。

### RQ3: 不同 family 的失败结构是否不同？

做 family-level breakdown。

重点看：

- 哪些模型在 B3 上更容易 internal exposure。
- 哪些模型在 C2.1/C2.2 上更容易被间接注入影响。
- 哪些模型在 A4 上更容易数据最小化失败。
- A2/A3/C1 虽然样本少，但能显示扩展风险面。

结论方向：

> Aggregate outcome scores hide substantial variation across failure families.

白话：

> 总分会掩盖问题，必须看每类风险。

### RQ4: 能否自动恢复失败归因？

跑：

- rule attribution baseline
- LLM-as-a-judge attribution

看：

- source accuracy
- channel accuracy
- mechanism accuracy
- component accuracy
- impact accuracy
- block point match
- failure chain overlap

预期稳妥结论：

> LLM-as-a-judge can recover coarse attribution signals, but fine-grained causal attribution remains challenging.

白话：

> LLM judge 大概能看出问题从哪来，但要精准判断完整因果链还不稳。

### RQ5: 多风险并存时，是否存在主导风险、masking 和顺序效应？

这是一个补充性的 compositional stress experiment，不替代主 `v0_2_test`，更适合作为消融、附加 RQ 或独立讨论段落。

跑独立的 `playground` 场景，构造：

- clean
- single hazard
- combo
- reverse combo

看：

- 多风险并存时，是否有一类风险在 outcome 上占据主导。
- 单一 hazard 的 effect 是否会被另一个 hazard mask 掉。
- `combo` 和 `reverse combo` 是否存在顺序效应。
- outcome-only 分数是否会掩盖 interaction / dominance / synergy。
- replay dominance 是否支持 YAML 里的 `dominant_hazard_hypothesis`。
- 某个 hazard 是真实被 agent 激活，还是只是配置在场景里但没有进入 failure path。

预期结论方向：

> In compositional settings, one hazard may dominate the observed failure, but interaction and order effects can still change the final outcome.

白话：

> 多个风险一起上时，常常会有一个更“抢眼”的主导风险，但顺序和交互也可能改变最后结果。

这里不要只用 outcome 分数判断 dominance。需要结合 replay：

- `replay_run_trace.py --stepwise-acceptance` 给出 first sensitive read / first untrusted sink / first risk-positive step。
- `analyze_replay_dominance.py` 按 composition group 比较 clean / single / combo / reverse combo。
- 如果 combo 的 first observed path 与某个 single hazard 的 replay path 重叠，才说该 hazard 被 observed failure path 支持。
- 如果 YAML 中有 hazard，但 single/control 和 combo replay 都没有触发对应 evidence，应当写成 configured but unactivated，而不是 dominant。

---

## 9. 可能形成的主要发现

### Finding 1: 强模型仍然会失败

即使是能力很强的模型，在工具调用、文件访问、外部内容、memory、多 agent 消息这些场景里仍然会出现安全失败。

### Finding 2: Guarded prompting 不足以作为防御

普通安全提醒不能稳定消除风险。这支持论文论点：

> Agent safety needs structural evaluation and diagnosis, not only better wording in prompts.

### Finding 3: 相同 outcome 分数背后可能是不同失败机制

两个模型 ASR 接近，不代表风险一样。

一个可能主要失败在 retrieved content，另一个可能主要失败在 memory，另一个可能主要失败在 multi-agent message。

### Finding 4: 内部权威污染值得单独研究

B1/B2/B3 可以支撑一个重要观点：

> Internal authority signals are a distinct and under-evaluated risk surface for agentic systems.

白话：

> 系统内部看起来可信的东西，反而可能是最容易让 Agent 放松警惕的地方。

### Finding 5: Trace-level latent violations 会暴露 endpoint 看不到的问题

最终答案没泄密，不代表过程安全。

例如：

- 中间读了 secret，但没输出。
- 中间暴露了内部消息。
- 中间调用了不该调用的工具。
- 中间形成了危险计划，但最后没完成。

论文里的说法：

> Endpoint safety does not imply trajectory safety.

白话：

> 最后没说出来，不代表中间没偷看过。

Replay analyzer 可以把这类 case 写得更扎实：不是只说 trace 文本里出现了某个动作，而是展示 fresh sandbox replay 后，哪一步第一次读到 sensitive path，哪一步第一次写入 watched path，哪一步第一次让 safety/risk probe 变成失败。

### Finding 6: 复合场景下可能出现主导、masking 或顺序效应

在多风险并存的 playground 里，单一风险不一定以线性方式叠加。

有些组合里，一个 hazard 可能主导失败；另一些组合里，顺序变化会改变 failure visibility 或归因结构。

这一 finding 应当使用 replay dominance 表支撑，而不是只看 combo 的最终 SVR。关键区分是：

- configured hazard：YAML 中存在的风险插件；
- activated hazard：replay path 中实际出现了对应 sensitive/sink/safety evidence；
- dominant hazard：combo 的 observed first failure path 与某个 single-control hazard path 最一致。

---

## 10. Case study 写法

不要写太多 case。建议 2-3 个。

每个 case 用统一模板：

1. 用户任务是什么。
2. 风险源是什么。
3. 风险从哪个 channel 进入。
4. Agent 第一个错误是什么。
5. 错误怎么传播。
6. 最终造成什么影响。
7. HoneyGuard 的 attribution 标签如何解释这个失败。
8. 如果要防，block point 在哪里。
9. replay evidence 是否复现并定位了这个 path。

推荐附一个 compact replay timeline：

```text
step 1: benign tool/read, no violation
step 2: first sensitive_read
step 3: first untrusted_sink or watched-path change
step 4: first risk_positive / safety_failure
```

如果是 compositional playground case，再补：

- single hazard path 是否在 combo 中复现；
- combo_reverse 是否改变 first failure step；
- observed dominant hazard 是否等于 `dominant_hazard_hypothesis`。

推荐 case 类型：

- 一个 C2.1 或 C2.2：展示外部内容 / 工具输出注入。
- 一个 B3：展示 multi-agent message 或 internal exposure。
- 一个 A2/A4：展示没有攻击者时也会失败。

---

## 11. 论文结构建议

### 1. Introduction

用一个具体 Agent 失败例子开头。

要表达：

- Agent 是多步执行系统。
- 最终答案安全不代表过程安全。
- outcome-only benchmark 不足。
- HoneyGuard 提供 trajectory-aware attribution benchmark。

### 2. Motivation / Background

讲：

- Agent 和普通 LLM 的区别。
- 工具、memory、retrieval、多 agent 带来的新风险面。
- 为什么需要归因。

### 3. Benchmark Design

讲：

- YAML scenario。
- sandbox execution。
- trace logging。
- trace replay validation。
- outcome criteria。
- attribution ground truth。
- A/B/C taxonomy。
- family design。

### 4. Metrics

分两类：

Outcome metrics：

- TSR
- SVR
- ASR
- STCR
- resource overrun
- latent violation
- unsafe internal exposure

Attribution metrics：

- source accuracy
- channel accuracy
- mechanism accuracy
- component accuracy
- impact accuracy
- block point match
- failure chain overlap

关键句：

> Outcome metrics say whether the run failed; attribution metrics say why it failed.

### 5. Experiments

围绕四个主 RQ，加一个 optional compositional RQ：

- RQ1: model comparison
- RQ2: naive vs guarded
- RQ3: family / attribution breakdown
- RQ4: automatic attribution with rule and LLM judge
- RQ5: optional compositional stress experiment for dominance / masking / order effects

### 6. Case Studies

用 2-3 个 trace 展示 HoneyGuard 怎么解释失败。

### 7. Discussion

讲：

- HoneyGuard 不是 defense。
- HoneyGuard 是 diagnosis benchmark。
- Attribution 可以帮助后续 defense 设计。
- LLM judge 有潜力但不完美。
- v0.2 是代表性覆盖，不是完整宇宙全集。

### 8. Limitations

必须主动承认：

- v0.2 family 不完全均衡。
- A2/A3/C1 每类只有 5 条。
- sandbox 场景是受控环境，不等同真实生产系统。
- LLM judge 细粒度归因仍不稳定。
- 当前没有声称提出新 defense。

---

## 12. 写作中要避免的坑

### 不要说覆盖所有 Agent 安全问题

应该说：

> We cover representative failure sources across non-adversarial, internal-compromise, and external-attack settings.

### 不要把 guarded 说成 defense

应该说：

> Guarded prompting is a weak prompt-only baseline, not a defense system.

### 不要说 LLM judge 完美自动归因

应该说：

> It provides scalable first-pass attribution signals, while fine-grained causal attribution remains challenging.

### 不要只报 overall ASR

当前 v0.2 是 155 条，而且 A2/A3/C1 只有 5 条。

所以必须：

- 报 aggregate。
- 报 family breakdown。
- 每个 family 显示 `x/n`。
- 单独说明 A2/A3/C1 是 promoted gap-family slices。

---

## 13. 最简论文摘要思路

可以按这个逻辑写摘要：

1. Agentic systems introduce safety failures that unfold over multi-step trajectories, not only final text outputs.
2. Existing benchmarks primarily report outcome metrics and often cannot explain where and why a failure occurred.
3. We introduce HoneyGuard, a trajectory-aware benchmark with structured attribution labels for source, channel, mechanism, first failed component, impact, block point, and failure chain.
4. HoneyGuard covers representative non-adversarial, internal-compromise, and external-attack scenarios in a reproducible sandbox.
5. Experiments across multiple models show that strong agents still fail, prompt-only safety reminders are insufficient, and similar outcome scores can hide different failure mechanisms.
6. Rule and LLM-based attribution analyses show that coarse attribution can be automated, but fine-grained causal attribution remains challenging.

---

## 14. 当前最稳的论文标题方向

偏稳：

> Beyond Outcome Metrics: A Trajectory-Aware Benchmark for Attribution-Level Agent Safety Evaluation

偏归因：

> From Outcomes to Causes: Attribution-Level Benchmarking of Safety Failures in Agentic Systems

偏系统评测：

> HoneyGuard: A Trajectory-Aware Benchmark for Diagnosing Agent Safety Failures

目前推荐第三个，清楚、直接，也适合后续开源项目名。
