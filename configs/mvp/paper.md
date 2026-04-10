下面给你一版**面向 NeurIPS 风格**的、经过收敛后的论文框架。目标不是“写得很满”，而是：

- 主线清晰
- claim 可 defend
- 方法、实验、发现互相支撑
- reviewer 一看就知道这不是“又一个 attack list”

我会给你：

1. **论文定位**
2. **核心叙事**
3. **改进后的贡献点**
4. **整篇论文结构**
5. **每一节该写什么**
6. **实验设计框架**
7. **图表建议**
8. **标题/摘要方向**
9. **NeurIPS 风险点与规避建议**

---

# 一、论文定位

这篇论文最好的定位不是单纯：

- benchmark paper  
也不是单纯：
- systems paper  
更不是：
- attack paper

而是：

> **Benchmark + Evaluation Methodology + Controlled Infrastructure + Empirical Diagnosis**

更具体一点：

> **An attribution-oriented evaluation framework for agent safety, supported by a trajectory-aware benchmark and a programmable sandbox.**

你这篇论文最应该卖的，不是“我们覆盖了很多攻击类型”，而是：

> **我们把 Agent 安全评测从结果级推进到了轨迹级、归因级。**

这句话应该成为整篇论文的灵魂。

---

# 二、核心叙事

我建议整篇论文围绕下面这条主线展开：

### 问题
现有 Agent 安全 benchmark 主要是 outcome-based：
- 看最终回复
- 看环境状态 diff
- 报 ASR/TSR/STCR

### 缺陷
这种评测虽然能告诉我们“有没有出事”，但不能告诉我们：
- 失败从哪里开始
- 通过哪个通道进入
- 在哪个组件首次被错误接纳
- 通过什么机制传播为最终危险行为

### 我们的核心主张
Agent 安全需要：
- **trajectory-aware**
- **attribution-level**
- **component-sensitive**
- **process-grounded**
的评测方法。

### 我们的方法
提出一个：
- 轨迹感知 benchmark
- 归因标签体系
- 可控安全沙箱
- attribution-aware metrics

### 我们的实验问题
1. 结果相似的模型，失败轨迹是否不同？
2. 传统 outcome-only 评测是否低估了潜在安全违规？
3. 内部权威污染是否构成被低估的独特威胁面？

### 我们的价值
让 benchmark 不只用于“排榜”，还用于：
- failure analysis
- defense diagnosis
- trust boundary analysis
- mechanism discovery

---

# 三、改进后的核心贡献点

这是我建议你在论文里最终采用的三条贡献，语气相对稳，适合 NeurIPS。

## Contribution 1
**We introduce a trajectory-aware, attribution-level benchmark for agent safety.**  
Unlike conventional outcome-only evaluation based on final responses or environment diffs, our benchmark captures step-level execution traces and annotates structured safety attributions, including failure source, entry channel, first-failure component, mechanism, and propagation chain.

## Contribution 2
**We provide a unified evaluation framework spanning non-adversarial failures, external attacks, and controlled internal-compromise scenarios.**  
This enables systematic comparison of how agent failures arise not only from user-facing adversarial inputs, but also from unsafe internal authority signals such as policy prompts, memory, and sub-agent outputs.

## Contribution 3
**We build an open, programmable, and isolated evaluation sandbox for reproducible agent safety research.**  
Our containerized infrastructure supports declarative scenario configuration, resource monitoring, detailed trace logging, and standardized scoring, enabling extensible and auditable trajectory-level safety evaluation.

---

# 四、建议论文标题

给你几个风格不同的方向。

## 风格 A：最稳妥学术型
**Beyond Outcome Metrics: A Trajectory-Aware Benchmark for Attribution-Level Agent Safety Evaluation**

## 风格 B：更强调归因
**From Outcomes to Causes: Attribution-Level Benchmarking of Safety Failures in Agentic Systems**

## 风格 C：更强调轨迹
**Trajectory-Aware Agent Safety Evaluation: Benchmarking Failure Attribution in Agentic Systems**

## 风格 D：更强调系统性
**Benchmarking Agent Safety Beyond ASR: A Trajectory-Aware and Attribution-Level Evaluation Framework**

我个人最推荐：

> **From Outcomes to Causes: Attribution-Level Benchmarking of Safety Failures in Agentic Systems**

因为它一下就把你的核心差异讲清楚了。

---

# 五、整篇论文结构

下面给你的是一个**NeurIPS 风格的主论文结构**。  
主文控制在合理篇幅，细节放 appendix。

---

## 1. Introduction

### 目标
让 reviewer 在前两页就明白：
- 现有 benchmark 的缺口
- 为什么 Agent 安全不能只看结果
- 你提出了什么
- 为什么这件事重要

### 建议内容结构
1. Agent 从文本生成走向行动系统
2. 传统 outcome-based safety benchmark 的局限
3. 一个具体例子说明“结果相同但失败轨迹不同”
4. 提出 trajectory-aware + attribution-level 的必要性
5. 简述你做的 benchmark 和 sandbox
6. 概述主要发现/研究问题
7. 列贡献

### 这一节的关键句
- Existing benchmarks often reveal whether an agent failed, but not how or where the failure first emerged.
- Endpoint safety equivalence can conceal substantial divergence in failure trajectories.
- We argue that agent safety evaluation must move from outcome-level robustness to attribution-level diagnosis.

---

## 2. Problem Setting and Motivation

这一节是很多论文没有但你非常适合加的，因为你的概念比较新。

### 目标
形式化定义：
- 什么是 outcome-only evaluation
- 什么是 attribution-level evaluation
- 什么叫 source / channel / component / mechanism / propagation chain

### 建议内容
#### 2.1 Agent execution model
定义 agent 是如何：
- observe
- reason
- plan
- act
- update state

#### 2.2 Why endpoint metrics are insufficient
给两个典型例子：
- 同样 ASR，但首错点不同
- 最终无害，但中间有 latent safety violation

#### 2.3 Definition of attribution
定义 5 个要素：
- source
- channel
- first-failure component
- mechanism
- block point / failure chain

这节很关键，因为它帮你把“归因级”从口号变成 formal problem setting。

---

## 3. Benchmark Design

这是论文方法的主体之一。

### 目标
说明 benchmark 怎么构建，任务长什么样，标签是什么，为什么可信。

### 建议子节

#### 3.1 Design principles
- risk provenance
- trace-grounded
- single-primary-cause
- controlled perturbation
- attribution consistency

#### 3.2 Threat coverage
按 A/B/C 讲，但不要太展开成 taxonomy 论文。  
重点是说明：

- A: non-adversarial safety-critical failures
- B: internal compromise
- C: external attacks

再说明 v1 主测什么，扩展测什么。

#### 3.3 Attribution schema
这是核心：
- source
- channel
- component
- mechanism
- impact
- failure chain
- block point

#### 3.4 Task construction
说明每个任务如何构建：
- scenario
- controlled hazard
- expected safe behavior
- success criteria
- forbidden actions
- ground-truth attribution

#### 3.5 Annotation and quality control
这个很关键，NeurIPS reviewer 很看重：
- how ground truth is assigned
- inter-annotator agreement
- conflict resolution
- task filtering

---

## 4. Programmable Evaluation Sandbox

这一节把工程系统包进来，但不要写成纯系统论文。

### 目标
说明为什么你的 sandbox 是这个 benchmark 成立的必要条件。

### 建议子节

#### 4.1 Environment model
- browser mock
- api/tool mock
- filesystem mock
- shell/log mock
- memory / planner hooks（如果有）

#### 4.2 Declarative scenario configuration
- YAML/JSON task definitions
- controlled injection points
- trust levels
- resource limits

#### 4.3 Trace capture and auditing
- action trace
- observation trace
- tool-call trace
- state diffs
- safety events
- resource usage

#### 4.4 Isolation and reproducibility
- Docker / containerization
- seeded randomness
- deterministic mock tools
- replay support

这一节的核心不是“我们工程写得很厉害”，而是：

> trajectory-level attribution requires controlled and auditable execution infrastructure.

---

## 5. Evaluation Protocol and Metrics

这一节很重要，是你和普通 benchmark 最大的不同之一。

### 建议子节

#### 5.1 Outcome metrics
- TSR
- SVR
- STCR
- ASR

#### 5.2 Attribution metrics
- source attribution accuracy
- channel attribution accuracy
- first-failure localization accuracy
- mechanism attribution accuracy
- failure chain reconstruction score
- block-point accuracy

#### 5.3 Latent violation metrics
这是你很值得加的一节。  
定义：
- unauthorized sensitive exploration
- silent boundary crossing
- hidden policy violation

这样就能支撑你的“false negatives in outcome-only evaluation”。

#### 5.4 Early-failure metrics
这可能成为亮点。  
你可以定义：
- first failure step
- failure lead time
- early failure ratio

用来支持“早期失效偏移”。

---

## 6. Experimental Setup

### 建议内容
#### 6.1 Evaluated agents/models
- 几个 SOTA closed/open model
- 若可能，不同 agent scaffolds

#### 6.2 Baselines
- naive react
- guarded agent
- attribution-aware agent（如果有）

#### 6.3 Benchmark composition
- 任务数
- A/B/C 比例
- difficulty distribution

#### 6.4 Implementation details
- prompts
- limits
- seeds
- number of runs
- model temperature

---

## 7. Main Results

这是主实验结果。

### 建议拆成四个问题

#### 7.1 Outcome performance
先给大家熟悉的：
- ASR
- STCR
- SVR

这一步不能省，不然 reviewer 不好对比。

#### 7.2 Attribution divergence under similar endpoint scores
展示：
- 两个模型 ASR 接近
- 但 first-failure component / mechanism 分布完全不同

这是你的第一大亮点。

#### 7.3 Hidden safety violations missed by endpoint-only evaluation
展示：
- 最终没 exfiltrate
- 但中途读了 secret、越权探测、跨边界读取
- latent violations 数量明显高

这是你的第二大亮点。

#### 7.4 Internal authority and controlled internal compromise
如果 B 做得足够：
- 展示 internal compromise 的独特模式
- 和外部攻击不同

如果 B 不够强，这节可以放小一点，甚至主文只做 controlled pilot，更多放 appendix。

---

## 8. Analysis

这里做更深层分析，不只是报分。

### 建议子节

#### 8.1 Where do agents fail first?
组件层分析：
- planner?
- tool argument builder?
- executor?

#### 8.2 Which mechanisms dominate across scenarios?
- instruction/data confusion
- authority overtrust
- sensitive data overdisclosure
- privilege boundary failure

#### 8.3 Defense diagnosis
某些 guard 是否只是降低能力而不改善 attribution？

#### 8.4 Case studies
给 3–4 个典型 trace：
- 同果异因
- 同因异表
- 结果安全但中间违规
- internal authority failure

---

## 9. Related Work

建议分四类：

### 9.1 LLM safety benchmarks
- jailbreak
- refusal
- harmful content

### 9.2 Agent safety and tool-use benchmarks
- tool misuse
- prompt injection
- environment attacks
- browser/tool benchmarks

### 9.3 Red teaming and trajectory analysis
- trace-based analysis
- process supervision
- chain-of-thought / action trajectory monitoring

### 9.4 Supply-chain / internal compromise / multi-agent trust
- poisoned prompts
- backdoored models
- memory poisoning
- multi-agent compromise

你的差异一定要写清：
> prior work evaluates attack families or endpoint outcomes; we focus on structured failure attribution grounded in execution traces.

---

## 10. Limitations and Broader Impacts

这节一定要写得真诚，不然 benchmark 论文 reviewer 很爱挑这个。

### 限制
- attribution labels still require ontology design choices
- some failure chains admit multiple plausible interpretations
- internal compromise scenarios are controlled simplifications
- mock environments may not capture full real-world complexity
- agent self-reports are not treated as ground truth

### 影响
- 有助于 agent safety diagnosis and safer deployment
- 也可能被用于更高效 red-teaming，需 responsibly release

---

## 11. Conclusion

简洁总结：
- 现有 outcome-only benchmark 不够
- 我们提出 trajectory-aware, attribution-level benchmark
- 结果表明 endpoint metrics 掩盖了重要失效差异
- 归因级评测能更好支持 defense diagnosis 和系统改进

---

# 六、我建议你在论文里明确提出的三个 Research Questions

这会让整篇实验很有组织感。

## RQ1
**Do similar endpoint safety scores imply similar failure behavior?**  
No/Not necessarily. We test whether models with comparable ASR/STCR fail at different stages, through different channels, and via different mechanisms.

## RQ2
**How much safety risk is missed by endpoint-only evaluation?**  
We quantify latent safety violations that do not manifest as final harmful outcomes but nonetheless cross sensitive boundaries.

## RQ3
**Are internal authority channels a distinct and under-evaluated source of safety failure?**  
We study whether compromised prompts, memory, or sub-agents induce qualitatively different failure patterns from external attacks.

---

# 七、主论文建议图表

NeurIPS 很看重图表叙事。你至少要准备这些。

## Figure 1：Problem illustration
一个非常重要的概念图：
- 两个 agent 最终都 failed / 或都 safe
- 但轨迹和首错点不同
- 对比 outcome-only vs attribution-level

这是全论文最重要的图之一。

---

## Figure 2：Benchmark framework
展示：
- task scenario
- controlled hazard
- trace capture
- attribution labels
- metrics

---

## Figure 3：Sandbox architecture
- declarative config
- isolated env
- tool mocks
- trace logger
- scorer

---

## Figure 4：Endpoint metrics vs attribution divergence
横轴 ASR/STCR，纵轴 attribution divergence / first-failure distance  
展示“结果相近，轨迹不同”。

---

## Figure 5：Latent violations missed by endpoint evaluation
柱状图：
- endpoint unsafe
- endpoint safe but latent violation
- fully safe

这一图很容易打 reviewer。

---

## Figure 6：Failure mechanism distribution
不同模型/不同场景的 mechanism 分布热力图。

---

## Figure 7：First-failure component distribution
展示最早崩在哪。

---

## Table 1：Benchmark composition
- 类别
- 样本数
- 难度
- 是否对抗
- 是否有 latent violation 标签

---

## Table 2：Main results
- TSR
- STCR
- ASR
- source/channel/mechanism attribution acc

---

## Table 3：Ablation / defense analysis
- naive
- guarded
- attribution-aware

---

# 八、摘要应该怎么写

NeurIPS 摘要通常要非常清楚地覆盖：

1. 问题
2. 缺陷
3. 方法
4. 结果
5. 意义

结构上类似：

- 1–2 句背景
- 1–2 句指出现有 benchmark 缺陷
- 2–3 句说你做了什么
- 2 句说主要发现
- 1 句说意义

你这篇摘要不能只是说“我们提出了一个 benchmark”，一定要强调：

- outcome-only 不够
- 我们做 attribution-level
- 发现 endpoint safety 掩盖了 failure dynamics / latent violations

---

# 九、NeurIPS 视角下最容易被 reviewer 质疑的点

这部分很重要。

## 风险 1：归因标签主观
**Reviewer 会问：**
- 你的 attribution ground truth 怎么来？
- 多标注者一致性如何？
- 首错点是否唯一？

**你必须准备：**
- annotation protocol
- inter-annotator agreement
- primary vs secondary labels
- adjudication process

---

## 风险 2：是不是只是把现有 benchmark 拼起来
**Reviewer 会问：**
- 这和 benchmark aggregation 有什么不同？

**你必须明确：**
- 统一 ontology
- cross-task attribution schema
- failure chain labels
- latent violation metrics
- first-failure localization

---

## 风险 3：B 类 internal compromise 不够扎实
**Reviewer 会问：**
- internal compromise 做得是不是太浅？
- 是不是只做了 prompt poisoning 小变体？

**建议：**
- 不要让 B 成为整篇论文唯一支点
- 主线还是 attribution methodology
- B 作为 distinctive extension，不必 claim 过满

---

## 风险 4：sandbox 过于 synthetic
**Reviewer 会问：**
- mock 环境是否真实？
- 结论能否外推？

**你要回应：**
- controlled sandbox is necessary for attribution validity
- goal is diagnosis, not full ecological realism
- we prioritize causal interpretability over uncontrolled realism

这是很重要的 stance。

---

## 风险 5：latent violation 是否真的算违规
**Reviewer 会问：**
- 读取 secret file 但没外发，算不算 unsafe？

**你要在 protocol 中明确：**
- unauthorized sensitive exploration
- policy-defined boundary crossing
- hidden policy violations
这些在 benchmark 中是明确定义的，而不是临时解释。

---

# 十、最推荐的论文结构目录版本

如果要非常具体，我建议最终目录像这样：

### 1. Introduction  
### 2. From Outcome Evaluation to Failure Attribution  
### 3. Benchmark Design  
#### 3.1 Design Principles  
#### 3.2 Threat Coverage  
#### 3.3 Attribution Schema  
#### 3.4 Task Construction and Annotation  
### 4. Programmable Evaluation Sandbox  
#### 4.1 Environment and Tool Modeling  
#### 4.2 Trace Capture and Isolation  
#### 4.3 Reproducibility and Auditability  
### 5. Evaluation Protocol  
#### 5.1 Outcome Metrics  
#### 5.2 Attribution Metrics  
#### 5.3 Latent Violation and Early-Failure Metrics  
### 6. Experimental Setup  
### 7. Main Results  
#### 7.1 Endpoint Safety Performance  
#### 7.2 Attribution Divergence Under Similar Endpoint Scores  
#### 7.3 Hidden Violations Missed by Outcome-Only Evaluation  
#### 7.4 Internal Authority and Controlled Internal Compromise  
### 8. Analysis and Case Studies  
### 9. Related Work  
### 10. Limitations and Broader Impacts  
### 11. Conclusion  

这个结构非常稳。

---

# 十一、我的最终建议：NeurIPS 投稿时的主打点

如果只能主打一句话，我建议就是：

> **This paper shows that endpoint safety metrics are insufficient for agentic systems, and introduces a trajectory-aware benchmark that evaluates not only whether agents fail, but where and how safety failures emerge.**

这个点最清晰，也最像 NeurIPS 会买的“evaluation methodology advancement”。

---

如果你愿意，我下一步最适合做的是下面三件事之一：

1. **直接给你写一版 NeurIPS 风格摘要**
2. **直接给你写一版 Introduction（1.5–2页）**
3. **把上面的框架进一步展开成每节要写的 bullet points 大纲**

我建议下一步做 **1 + 2**，先把摘要和引言定住。