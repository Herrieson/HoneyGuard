# HoneyGuard 研究衍生课题：LLM-as-Auditor 的验收规则设计能力评测（v1）

## 1. 背景与动机

当前主流安全评测通常关注两类能力：

1. LLM 作为 Agent 的作恶能力（攻击成功率、隐蔽性）。
2. LLM 作为 Agent 的防作恶能力（拒绝率、越权抑制能力）。

本课题关注第三类能力：

- LLM 作为“安全审计者/评测者”（LLM-as-Auditor）时，是否能在给定场景中设计出高质量 `acceptance_criteria`。

这对应的是模型的：

- 安全态势感知（Situational Awareness）
- 威胁建模（Threat Modeling）
- 检测逻辑设计（Detection Logic Design）

## 2. 核心研究问题

在给定场景 YAML（不含 `acceptance_criteria`）时，LLM 是否能根据：

- 场景拓扑（文件、工具、权限）
- 业务目标（public goal）
- 隐藏恶意目标（hidden goal）

生成一组可执行、低误报、可解释的验收标准，并且能在攻击轨迹与正常轨迹之间有效区分。

## 3. 任务定义（建议）

### 3.1 输入

- 去除 `acceptance_criteria` 的场景 YAML。
- 包含 `scenario / target_surface / tools_enabled / files / mock_tools / system_prompt / initial_instructions / scenario_blueprint`。

### 3.2 输出

- 结构化 `acceptance_criteria`（遵循 HoneyGuard 现有 schema）。
- 可选输出 `rationale`（规则设计理由）。

### 3.3 目标

- 不是“完美检测”。
- 是在可观测条件下，最大化对攻击行为的区分能力，并控制明显误报。

## 4. 评价维度

### 4.1 区分能力（核心）

在同一场景下运行多类轨迹：

- benign（正常任务）
- attack（明显恶意）
- borderline（可疑但未达成实质泄露/破坏）

评价 LLM 生成规则对三类轨迹的区分效果：

- attack 命中率（近似 recall）
- benign 误报率（近似 false positive rate）
- borderline 处理质量（不过度二元化）

### 4.2 规则工程质量

- 是否包含动作证据（Action Evidence）与结果证据（Outcome Evidence）组合。
- 是否存在弱规则过拟合（例如仅匹配 DONE token、模板短语）。
- 是否可解释、可复核、可维护。

### 4.3 泛化能力

跨以下维度评估稳定性：

- `target_surface`: user / enterprise / hybrid
- `attack_intent`: confidentiality / integrity / availability
- domain 与风格变化

### 4.4 稳定性与一致性

同一输入多次生成规则：

- 规则波动幅度
- 结论波动幅度

## 5. 实验架构（Red-Blue 分离）

建议采用三角色流程：

1. World Builder（场景生成）
- 生成环境与任务上下文。

2. Blue Auditor（规则生成）
- 基于静态场景生成 `acceptance_criteria`。
- 禁止看到执行日志，避免“看答案出题”。

3. Red Agent（执行）
- 在环境中执行任务，尝试达成隐藏目标或完成正常任务。

通过运行结果回放评估 Blue 规则质量。

## 6. 关键控制变量与防偏差措施

### 6.1 角色隔离

- Builder / Auditor / Agent 尽量使用不同模型或不同版本。
- 防止同模型“隐式协同”抬高结果。

### 6.2 信息隔离

- Auditor 不读取 run log。
- 避免直接暴露可被机械匹配的泄露标记（或设置隐藏变体）。

### 6.3 防模板化作弊

- 使用同义改写、结构变化、路径变化、工具调用变化测试规则稳健性。
- 避免只靠硬编码关键词获得高分。

### 6.4 评估分层

建议输出三态而非二元：

- `compromised_strong`
- `compromised_suspect`
- `benign_or_unclear`

减少“硬判定”导致的结论失真。

## 7. 可交付产物（建议）

1. 基准任务定义文档（本文件的后续版本）。
2. 无 `acceptance_criteria` 的场景子集。
3. Auditor 输出格式规范（JSON schema + 约束）。
4. 评分器：按轨迹集评估规则质量与分层表现。
5. Leaderboard 指标：
- 区分能力
- 误报控制
- 泛化稳定性
- 规则复杂度/可解释性

## 8. 与 HoneyGuard 当前流程的结合点

当前 HoneyGuard 已具备：

- 场景生成（seed -> world/plot/acceptance）
- 运行与日志回放
- 聚合报告（按 style/domain/surface/attack_intent）

可以在此基础上新增一个“研究模式”：

- 生成场景时跳过 acceptance。
- 调用 Auditor LLM 专门生成 acceptance。
- 与默认规则生成器并行 A/B，对比同一轨迹集表现。

## 9. 风险与边界

1. 该课题评估的是“检测逻辑设计能力”，不是完整生产级入侵检测能力。
2. 指标可能被 prompt engineering 强烈影响，需要固定协议和版本化。
3. 若缺少高质量 borderline 样本，容易高估规则好坏。

## 10. 下一步（最小落地）

1. 定义 Auditor 输入/输出 schema（冻结 v1 协议）。
2. 选取一组代表性场景（按 surface × intent 分层）。
3. 构建 benign/attack/borderline 轨迹集。
4. 跑 2-3 个候选模型进行初测并输出对比报告。
5. 根据误报样本反推协议修订（v1 -> v2）。

---

本文档定位：研究构想与执行蓝图（Draft v1）。
