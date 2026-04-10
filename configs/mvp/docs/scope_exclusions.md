# HoneyGuard MVP Scope Exclusions v0.1

## 1. 文档目的

本文件用于明确 HoneyGuard v0.1 **暂不纳入** 的内容，避免后续在 benchmark 扩展、场景设计和论文叙事上不断失焦。

本文件的作用不是否定这些方向的重要性，而是保证 v0.1 保持：

- 可控
- 可复现
- 可归因
- 可在合理周期内完成

---

## 2. v0.1 明确不做的内容

### 2.1 不做真实互联网浏览

v0.1 不要求接入开放互联网，也不以真实在线网页抓取作为主要场景依赖。

原因：

- 外部页面内容高度不稳定，不利于复现
- 难以控制注入点与地面真值
- 会显著增加 attribution validity 风险

替代方案：

- 使用可控网页 mock
- 使用本地文档 / 检索片段 / sandbox 文件模拟 observation channel

### 2.2 不做真实 OS 提权或宿主级危险操作

v0.1 不追求真实权限提升、宿主机破坏、容器逃逸、真实网络横向移动等高风险系统攻击。

原因：

- 这类任务对安全隔离与运维要求过高
- 容易把项目重心从 benchmark methodology 拉向 offensive systems engineering
- 对归因主线帮助有限

替代方案：

- 在容器沙箱内用 mock 权限、假凭证、受控命令和策略约束模拟风险边界

### 2.3 不做大规模多 Agent 场景

v0.1 不以复杂多 Agent topology 为主战场，不追求 planner-executor-reviewer-swarm 等大规模协作图谱覆盖。

原因：

- 多 Agent 会放大归因歧义
- 会提高 annotation 成本与首错点判定难度
- 容易让实验故事被系统复杂度淹没

允许的例外：

- 若为验证 internal authority pilot，允许极小规模、强可控的双 agent / 三角色设置

### 2.4 不追求覆盖所有 attack family

v0.1 不追求把 jailbreak、prompt injection、memory poisoning、tool misuse、privacy leakage、multi-agent compromise 等所有 attack family 一次性纳入主 benchmark。

原因：

- 全覆盖会立即稀释主线
- 样本数量增加不等于归因质量提升
- 容易退化为 benchmark aggregation

冻结结论：

- 先聚焦 `A1`、`A4`、`C2.1`、`C2.2`

### 2.5 不把 B 类 internal compromise 作为主线主体

v0.1 不以大规模 internal compromise benchmark 为交付目标。

原因：

- B 类有研究价值，但建模与标注复杂度高
- reviewer 也更容易质疑其真实性与代表性
- 在当前阶段，B 类更适合作为 methodology 的补充验证，而非唯一卖点

允许的形式：

- 小规模 pilot
- appendix 或次级实验
- 用于展示 authority_overtrust 的独特模式

---

## 3. 设计边界原则

后续所有任务扩展必须通过以下边界原则审查。

### 3.1 归因有效性优先于生态真实性

如果一个场景更“像真实世界”，但无法稳定定义主因、failure chain 与 block point，则不应优先纳入 v0.1。

### 3.2 单主因优先于复合威胁

每个样本优先只注入一个主要风险源。多因素叠加即使更逼真，也会显著降低可解释性和标注一致性。

### 3.3 评测方法优先于攻击收集

HoneyGuard v0.1 的目标是建立 attribution-level evaluation methodology，而不是证明“我们收集了最多场景”。

### 3.4 可复现优先于开放世界依赖

任何依赖实时网页、动态服务、外部账户状态、不可控第三方 API 行为的设计，默认不纳入 v0.1 主 benchmark。

---

## 4. 当前阶段的非目标

以下内容即使未来可能需要，也不属于 v0.1 的直接成功标准：

- 构建全面的 Agent threat taxonomy
- 追求真实生产环境部署级防御闭环
- 对所有模型 / 所有 agent scaffold 做大规模排行
- 一次性做完完整的 B 类和多 Agent 安全研究
- 证明 benchmark 已覆盖现实世界 Agent 安全的全部风险面
- 构建依赖 agent 自我解释的归因体系

v0.1 更现实的目标是：

- 构建一个可 defend 的最小 benchmark
- 跑出能支撑论文主张的归因信号
- 证明 outcome-only 评测确实漏掉了关键安全信息

---

## 5. 纳入 v0.1 的判断标准

后续新增内容只有在同时满足下列条件时，才适合进入 v0.1 主线：

1. 有清晰、单一、可控的主要风险源。
2. 能稳定记录支持归因的 step-level trace。
3. 能定义 expected safe behavior、forbidden actions 与 latent violation。
4. 能较高一致性地标注 source、channel、component、mechanism。
5. 能帮助回答 RQ1 或 RQ2；若是 B 类试点，则至少能补充 RQ3。

若某项工作不满足这些条件，则应：

- 推迟到 v0.2
- 作为 appendix / future work
- 或仅保留为内部探索，不进入主 benchmark

---

## 6. 一句话边界总结

HoneyGuard v0.1 的边界不是“做尽可能多的 Agent 安全任务”，而是：

> **在现有基础设施上，做一个范围收敛、主因清晰、轨迹可审计、归因可 defend 的最小可行 benchmark。**
