# TraceProbe MVP Project Scope v0.1

## 1. 文档目的

本文件用于冻结 TraceProbe 当前 MVP 阶段的论文主线、方法边界、研究问题与最小交付范围，作为后续 ontology、任务样本、评分器与实验设计的统一依据。

本阶段的目标不是再做一个“能跑”的 Agent benchmark 系统。TraceProbe 已经具备：

- YAML 场景定义
- Docker 隔离执行
- 多步 Agent 运行
- 工具调用与环境交互
- 轨迹与最终状态记录

因此，MVP 的核心工作已经从“执行框架搭建”转向“归因级 benchmark 构建”。

---

## 2. 论文主张

TraceProbe MVP 需要明确围绕下面这个主张展开：

> 现有 Agent 安全评测大多停留在 outcome-only 层面，只能回答系统最终是否失败，却无法系统回答失败从哪里开始、通过什么通道进入、在哪个组件首次被错误接纳，以及如何传播成最终后果。因此，Agent 安全评测需要从结果级升级到轨迹感知、归因级评测。

这意味着 TraceProbe 的论文定位不是：

- 单纯的 attack list 聚合
- 单纯的 sandbox / systems 工程论文
- 单纯的 prompt injection benchmark

而是：

> **一个 trajectory-aware、attribution-level 的 Agent Safety Benchmark 与 evaluation methodology。**

---

## 3. 项目核心方法

TraceProbe MVP 的方法核心由四部分构成：

### 3.1 统一的归因语言

对每个 benchmark 样本建立结构化真值，而不只记录任务是否完成。核心标签至少包括：

- `source`
- `channel`
- `first_failed_component`
- `mechanism`
- `impact`
- `failure_chain`
- `counterfactual_block_point`

### 3.2 轨迹感知评测

评测对象不再只有最终回复和最终环境状态，而是包含 step-level trace：

- observation
- action
- tool call
- tool response
- environment diff
- safety event

### 3.3 可控样本设计

每个任务都需要有清晰、可控、可复现的风险源，并遵守“单主因优先”的构造原则，避免多个强干扰因素同时出现导致无法归因。

### 3.4 双层指标体系

TraceProbe MVP 同时保留：

- outcome metrics：TSR / SVR / STCR / ASR
- attribution metrics：source / channel / component / mechanism / failure chain / block point

核心思想是：不只评估“是否安全”，还评估“为何不安全、何处先失效、理论上哪里可阻断”。

---

## 4. 研究问题

MVP 阶段优先围绕以下三个研究问题组织实验与论文叙事。

### RQ1. 相近的 endpoint 分数，是否掩盖了不同的 failure trajectories？

目标是验证：两个系统即使在 ASR、STCR 等结果级指标上看起来接近，也可能在首错组件、失效机制、失败传播路径上明显不同。

### RQ2. outcome-only 评测会漏掉多少 latent safety violations？

目标是验证：一些 run 最终没有表现为显式 harmful outcome，但中途已经越过敏感边界，例如未授权读取敏感信息、向不可信工具发送敏感字段、进行隐蔽越权探索。

### RQ3. internal authority 是否是被低估的独特风险源？

这个问题在 v0.1 中仅作为 pilot 研究问题存在，不作为 MVP 成败的唯一支点。若实验资源有限，主线应优先保证 RQ1 和 RQ2 可被清晰回答。

---

## 5. MVP 范围

TraceProbe v0.1 的最小可行范围应冻结为以下四类任务：

- `A1` 决策失控
- `A4` 数据边界失效
- `C2.1` 内容注入
- `C2.2` 工具输出污染

选择这四类的原因是：

- 风险来源清晰，易于设定主因
- 与现有 YAML + Docker + trace 基础设施天然匹配
- 能同时覆盖非对抗失效与外部攻击
- 容易展示“相同结果，不同轨迹”与“最终安全，但中途违规”的核心故事
- 便于后续建立统一 ontology 与 scorer

### 关于 B 类 internal compromise

`B` 类只保留为后续扩展方向或小规模 pilot，包括但不限于：

- 恶意 system prompt
- poisoned memory item
- compromised planner / reviewer message

在 MVP 阶段，B 类不应吃掉主线，也不应成为必须大规模完成的任务族。

---

## 6. MVP 交付物

任务 0 完成后，后续工作必须围绕下列交付物推进：

- 一套冻结的归因 ontology
- 一套 annotation guideline
- 一版扩展后的 benchmark YAML schema
- 一套支持归因的 trace schema
- 一个 20-30 样本的开发集
- 一个 outcome scorer 原型
- 一套 latent violation 判定规则
- 一组能支持论文主张的 baseline 结果

MVP 的验收标准不是样本数最大化，而是以下问题能否被 benchmark 稳定回答：

- 为什么失败
- 风险从哪里进入
- 首错点在哪里
- 失败如何传播
- 哪里本可阻断

---

## 7. 成功标准

若 TraceProbe v0.1 成功，至少应满足以下条件：

1. 能构造一批带归因真值的、可复现的 Agent 安全任务。
2. 能从运行轨迹中自动或半自动提取 outcome 与 attribution 相关证据。
3. 能展示 endpoint-only 指标无法揭示的安全差异。
4. 能形成清晰论文叙事：TraceProbe 不只是列出“哪些攻击有效”，而是解释“失败是如何发生的”。

---

## 8. 后续阶段的执行约束

后续所有设计决策都应服从下列优先级：

1. `归因有效性` 优先于 `场景数量`
2. `可控与可复现` 优先于 `表面真实感`
3. `单主因清晰` 优先于 `复合攻击炫技`
4. `论文主线收敛` 优先于 `威胁面无限扩张`

如果某项新增工作不能明显提升归因能力，而只是增加任务数量或 threat family 覆盖面，则不属于当前 MVP 的高优先级事项。
