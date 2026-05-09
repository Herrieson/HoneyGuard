# HoneyGuard v0.2 Experiment Matrix

本文档把 v0.2 相关实验按“主 benchmark、条件对照、校准子集、stress suites、后分析层”拆开，避免把不同目的的实验混成一个 leaderboard。

核心原则：

- `v0_2_test` 是主 benchmark。
- `guarded` 是同一主 benchmark 上的 prompt-only 对照，不是新任务集。
- `v0_2_small`、`v0_2_task_hard`、`v0_2_risk_broad`、`v0_2_attack_hard` 是建议的派生 stress suites，当前可视为设计层或后续实现层，不要和主 benchmark 混算。
- `v0_2_transient` 是 trajectory-safety pilot。
- compositional playground (`mvp_compositional_playground`) 是多风险组合 stress suite。
- trace replayer 是后分析层，不是数据集。

---

## 1. 当前已经 materialize 的套件

| Suite | Status | Size | What it tests | Reporting rule |
|---|---|---:|---|---|
| `v0_2_test` | current | 155 | 主 benchmark，覆盖 A/B/C 三类风险源 | 主 leaderboard 只看它 |
| `v0_2_test + guarded` | current condition | 155 | prompt-only safety reminder 的影响 | 作为 paired comparison，不是新 split |
| `v0_2_transient` | current pilot | 8 | 过程安全、短暂越界、最终恢复/未恢复 | 不并入主 leaderboard |
| compositional playground (`mvp_compositional_playground`) | current stress suite | recipe-driven | 多风险并存下的 dominance / masking / order effect | 只做 supplementary RQ 或 appendix |
| `trace replayer` | current analysis layer | N/A | trace fidelity、step-level failure localization、dominance support | 适用于所有 suites |

### 1.1 `v0_2_test`

这是主数据集，也是论文 headline 结果的唯一主来源。

它回答：

- 不同模型在 HoneyGuard 上表现如何？
- 不同 family 的失败结构是否不同？
- attribution labels 是否能被规则或 LLM judge 恢复？

### 1.2 `v0_2_test + guarded`

这不是新 split，而是同一主数据集上的 baseline condition。

它回答：

- safety-aware prompting 是否改变风险？
- prompt-only reminder 是否足以作为防御？

### 1.3 `v0_2_transient`

这是 trajectory-safety pilot。

它回答：

- endpoint-safe 是否掩盖过程越界？
- final state 清洁是否意味着执行过程安全？
- latent violations 是否能被 trace 和 replay 捕捉？

### 1.4 compositional playground (`mvp_compositional_playground`)

这是多风险组合 stress suite。

它回答：

- 多风险并存时，是否存在主导风险？
- masking、amplification、order effect 是否出现？
- 配置的 hazard 和实际激活的 hazard 是否一致？

---

## 2. 建议保留的派生 stress suites

这些名字代表论文和实验设计中建议保留的扩展条件。它们的实现方式可以是：

- 独立 preset split
- 固定 sampled subset
- wrapper-only preset
- 或后续按需 materialize 的实验目录

当前不应把它们直接视为和 `v0_2_test` 同等级的主 leaderboard。

| Suite | Status | Suggested size | What it tests | Typical use |
|---|---|---:|---|---|
| `v0_2_small` | planned / derived | 24 | 与全集 ASR 近似的 calibrated subset | 大量模型的低成本 screening |
| `v0_2_task_hard` | planned | small | 更复杂任务条件下的安全表现 | task complexity stress |
| `v0_2_risk_broad` | planned | small | 更广义风险面的外推能力 | risk extensibility check |
| `v0_2_attack_hard` | planned | small | 更强攻击下的鲁棒性 | 只跑主实验表现好的模型 |

### 2.1 `v0_2_small`

这是一个校准子集，用来降低额外模型的运行成本。

建议要求：

- 任务数少，但要保持 ASR / SVR / family 覆盖与全集近似。
- 只能用于 screening 或 appendix，不用于 headline 结论。
- 最好在文档中固定抽样规则或固定样本列表，避免临时挑样。

### 2.2 `v0_2_task_hard`

这是任务复杂度压力测试，而不是新攻击集。

建议强调：

- 复杂度提高，但攻击语义尽量可控。
- 关注长上下文、多步执行、更多工具、更多文件、更多决策点。
- 主要回答“复杂任务是否放大 boundary violation”。

### 2.3 `v0_2_risk_broad`

这是更广义风险的扩展套件。

建议强调：

- 用来测试框架可扩展性。
- 不要暗示它覆盖了所有 agent safety 风险。
- 更适合作为 supplementary discussion 或 appendix。

### 2.4 `v0_2_attack_hard`

这是更强攻击压力测试。

建议强调：

- 只对表现较好的模型跑。
- 看标准攻击之外的 robustness。
- 不要和主 benchmark 混成同一张总表。

---

## 3. trace replayer 的位置

trace replayer 不属于 split，也不属于主 leaderboard。

它是所有 suite 的后分析层，负责：

- exact replay validation
- stepwise safety diagnosis
- watched-path diff
- compositional dominance support

建议输出的 analysis artifact：

- `replay.rows.jsonl`
- `replay.rows.csv`
- `replay.steps.jsonl`
- `replay.summary.json`
- `replay_dominance.*`（只对 compositional suite）

---

## 4. 推荐实验矩阵

如果目标是写 EMNLP 主文，推荐按下面顺序组织实验：

1. 主 benchmark：`v0_2_test`
2. 条件对照：`v0_2_test + guarded`
3. 归因分析：rule attribution / LLM judge
4. 过程安全：`v0_2_transient` + replay
5. 复合压力：compositional playground (`mvp_compositional_playground`) + replay dominance
6. 补充 stress suites：`v0_2_small`、`v0_2_task_hard`、`v0_2_risk_broad`、`v0_2_attack_hard`

报告规则：

- 主 leaderboard 只看 `v0_2_test`。
- `guarded` 用 paired delta 表。
- `v0_2_small` 只用于 screening。
- `v0_2_transient`、`v0_2_task_hard`、`v0_2_risk_broad`、`v0_2_attack_hard`、compositional playground 都应明确标成 supplementary / stress / pilot。
- replay 结果与主 benchmark 结果分开展示。

---

## 5. 当前和 future work 的边界

如果某个 suite 还没有对应的 preset 实现，不要在论文正文里把它写成已经跑过的主结果。

建议做法：

- 文档里把它标为 `planned / derived`
- 论文里只在 design 或 future work 中提及
- 真正数值结果只引用已经 materialize 的 suite

这样可以避免后续出现“实验名已经写进论文，但代码里还没定版”的问题。
