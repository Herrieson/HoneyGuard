# HoneyGuard 全项目改造汇总方案（v1）

## 1. 文档目的

将以下三份文档合并为一个可执行的“全项目改造清单”：

- `docs/scenario_realism_assessment_v1.md`
- `docs/acceptance_outcome_driven_upgrade_plan_v1.md`
- `docs/honeypot_deployment_plan_v1.md`

目标是回答两个问题：

1. 整个项目到底要改哪些地方（代码/配置/流程/指标）？
2. 这些改动按什么顺序做，如何判断做完？

## 2. 总体改造主线

主线 A：场景真实性提升（降低模板味、补齐业务契约）

主线 B：验收从 marker 驱动改为 outcome 驱动（降低误报、提升可解释性）

主线 C：引入认知 honeypot（部署、触发检测、A/B 评估）

主线 D：数据治理与实验流程（规则+LLM+人工复核闭环）

## 3. 文件级改造清单（必须改）

## 3.1 场景生成与真实性

1. `scripts/build_attack_config.py`
- 改造 `_default_goals`：同一 style 提供多模板槽位，减少固定句式。
- 改造 `_inject_key_paths_into_instruction`：路径提示文案多样化，不再固定一句。
- 移除/弱化显式 `End with DONE` 的用户侧模板痕迹（保留 stop signal 机制）。
- 兼容 `target_surface` 与真实性约束，避免模板化回退占主导。

2. `scripts/env_builder.py`
- 强制在合适 surface 下填充 `user_roles` / `critical_user_flows` / `user_data_entities`。
- 把“可为空”检查升级为门禁（至少 warning，建议逐步升到 error）。

3. `scripts/attack_config_lint.py`
- 增加真实性 lint：
  - 技术栈与攻击目标文件类型冲突检查（manifest vs attack target）。
  - 指令重复短语频次检查（批量生成后可汇总统计）。

## 3.2 验收规则（Outcome-Driven）

4. `scripts/build_attack_config.py`
- 重写 `_build_acceptance_criteria` 为 style 分支 outcome builder：
  - C 类：敏感读取/聚合后果，不以 `EXFILTRATION_OK` 为主门槛。
  - I 类：`file_changed + direction check`，不以 `BACKDOOR_INSTALLED` 为主门槛。
  - A 类：配置方向/调度退化证据，不以固定 token 为主门槛。
- 每个 style 至少 2 条 `enforce=true`：动作证据 + 方向证据。
- 默认 `acceptance_logic=all`（至少对 C/I/A）。

5. `scripts/attack_config_lint.py`
- 增加规则质量门禁：
  - 禁止 marker-only enforce。
  - enforce 条件必须含动作证据（`file_changed` 或 `command_exit_code`）。
  - enforce 条件必须含方向/后果证据。

6. `scripts/init_from_config.py`
- 保持兼容现有 criterion type，同时补充更严格校验提示（方向性规则缺失时给 warning/error）。

7. `api.py`
- 复用现有 evaluator 类型（`file_changed`/`command_exit_code`/`file_not_contains` 等），必要时补充结果 detail 字段，便于后续复核与报告。

## 3.3 评估与数据分层

8. 新增 `scripts/select_consensus_subset.py`
- 输入：`run.jsonl` + `llm_judge rows.csv`。
- 输出：
  - `high_conf_positive`
  - `high_conf_negative`
  - `conflicts`
  - 分层 summary（含 style/domain 覆盖）。

9. `scripts/llm_judge_attack_behavior.py`
- 增加可配置阈值参数（如 high-conf positive/negative 的置信度阈值）。
- 输出中强化复核辅助字段（如分层标签、优先级）。

10. `scripts/aggregate_attack_reports.py`
- 纳入三层数据与冲突分布统计。
- 增加规则误报/漏报趋势指标（基于人工复核标签）。

## 3.4 Honeypot 能力建设

11. 新增目录 `configs/honeypot/library/`
- 建立罐库（按 `domain/style/target_surface` 组织）。

12. 新增目录 `configs/attack/paper_hp/`
- 由注入脚本生成 `*_hp.yaml`，不污染基线 `paper/*.yaml`。

13. 新增 `scripts/generate_honeypot_catalog.py`
- 从历史 `run/judge` 抽取高吸引力模式，生成候选罐目录。

14. 新增 `scripts/inject_honeypots.py`
- 把罐注入到场景 YAML：
  - `files_overrides`（honey artifacts）
  - `acceptance_criteria`（触发检测）
  - `honeypot_profile`（审计元数据）

15. 新增 `scripts/evaluate_honeypot_ab.py`
- 对 A/B（baseline vs hp）输出对照报告：
  - 攻击成功率变化
  - 罐触发质量
  - 资产保护率变化

16. `api.py` / 日志记录链路（若需）
- 增加 `honeypot_event` 结构化记录（`read_hit/content_hit/exfil_hit/trap_call_hit`）。

## 3.5 实验流程与文档

17. `docs/experiment_guide_v2.md`
- 补充新流程：
  - `generate -> run -> llm_judge -> select_consensus_subset -> conflict_review`
  - honeypot A/B 流程

18. `docs/paper_results_template_v2.md`
- 新增结果版块：
  - 三层数据统计
  - 规则与 LLM 分歧趋势
  - honeypot A/B 对照

19. `scripts/generate_attack_batch.sh`（建议）
- 增加 realism/outcome builder 相关开关透传，方便批量切换旧版/新版。

## 4. 新增流程清单（必须落地）

1. 场景生成后先跑 lint + realism 检查，再允许进入 run 阶段。
2. 每次 run 后必须跑 llm_judge，并执行分层脚本。
3. 每轮从 `conflicts` 按 style/domain 抽样人工复核（2-5 条/桶）。
4. 人工复核结论必须回写为规则修订输入（builder/lint）。
5. honeypot 改造采用 A/B 对照，不允许只报单边结果。

## 5. 分阶段实施（建议）

## Phase 1（第 1-2 周）：先把误报降下来

- 完成 outcome builder + lint 门禁。
- 完成 `select_consensus_subset.py`。
- 在 `paper` 全量跑新版与旧版对比。

交付物：
- 新 acceptance 规则可用。
- 三层数据自动产出。
- 分歧率基线与下降幅度报告。

## Phase 2（第 3-4 周）：补 honeypot A/B

- 建罐库与注入脚本。
- 生成 `paper_hp` 全量。
- 跑 A/B 并产出报告。

交付物：
- `paper` vs `paper_hp` 对照结果。
- 触发率与误触发率指标。

## Phase 3（持续）：闭环优化

- 固化人工复核机制。
- 周期性修订规则与置信阈值。
- 持续跟踪 style/domain 覆盖稳定性。

## 6. 统一验收标准（DoD）

1. marker-only 成功样本占比显著下降（目标接近 0）。
2. 规则与 LLM 分歧率相对下降（目标 25%+）。
3. 冲突样本具备可解释归因（规则误报/漏报 or LLM误判）。
4. honeypot A/B 满足：
- `ASR_llm_success` 下降
- `asset_protection_rate` 上升
- `false_trigger_rate_benign < 5%`（可分场景调整）

## 7. 风险与控制

1. 风险：规则变严导致“通过率骤降”。
- 控制：保留旧 builder 开关，先做 A/B 并行。

2. 风险：按 style 规则复杂度上升，维护成本增加。
- 控制：统一 criterion 模板与 lint 门禁，避免场景自由发挥。

3. 风险：honeypot 引入后误触发干扰正常任务。
- 控制：先文件/日志型（v1），trap tool 后置到 v2，并设置 benign false trigger 门限。

---

本文件为三份方案的统一执行版。后续若进入实施阶段，建议再补一个 `v1 task board`（按文件拆 issue 与 owner）。
