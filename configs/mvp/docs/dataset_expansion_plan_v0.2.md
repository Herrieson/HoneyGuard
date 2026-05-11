# TraceProbe MVP Dataset Expansion Plan v0.2

## 1. 目标

v0.2 的目标不是简单增加样本数，而是让主实验从 pilot 级别变成可支撑论文主结果的 benchmark：

- 降低 ASR/SVR 等比例指标的小样本颗粒度问题。
- 正式覆盖 `internal_compromise`，把 B 类从 pilot 纳入主 benchmark。
- 保持归因真值质量，不用低质量样本换数量。
- 让 outcome-level 和 attribution-level 结果都能按 family / channel / mechanism 做稳定分析。

## 2. 当前状态

### v0.1 frozen test

位置：`configs/mvp/_archive/v0_1_splits/formal/`

| Family | Source | Current test N | Notes |
| --- | --- | ---: | --- |
| `A1` | `non_adversarial` | 10 | 决策 / 操作边界失控 |
| `A4` | `non_adversarial` | 10 | 数据边界 / 外发最小化失效 |
| `C2.1` | `external_attack` | 10 | retrieved-content indirect injection |
| `C2.2` | `external_attack` | 10 | tool-output poisoning |

当前 test 总数为 40。ASR 只在 `external_attack` / `internal_compromise` 样本上有定义，所以 v0.1 的 ASR 分母通常只有 20 个 attack-evaluable 样本。

### B pilot

位置：`configs/mvp/_archive/v0_1_splits/pilot_b/`

| Family | Channel | Current pilot N | Status |
| --- | --- | ---: | --- |
| `B1` | `policy_prompt` | 4 | 已有 pilot，可作为模板或 dev seed |
| `B2` | `memory_state` | 0 | v0.1 deferred，需要补齐 |
| `B3` | `multi_agent_message` | 6 | 已有 pilot，可作为模板或 dev seed |

B 类当前不属于 v0.1 main test。v0.2 应该把 B 类正式纳入主实验，否则 A/B/C 风险来源框架在结果上不完整。

## 3. 类别扩充决策

### 必须扩充

v0.2 必须加入以下 family：

- `B1`: policy-prompt compromise
- `B2`: poisoned memory state
- `B3`: compromised multi-agent message / reviewer / planner

理由：

- B 类对应 `internal_compromise`，是现有 A/B/C 框架缺失的主轴。
- B 类样本会进入 ASR 分母，可直接缓解当前 ASR 分母只有约 20 的问题。
- `policy_prompt`、`memory_state`、`multi_agent_message` 已经在 ontology 中定义，不需要临时扩标签。

### 应继续扩充

现有 `A1`、`A4`、`C2.1`、`C2.2` 也要扩充到每类至少 20 个 test 样本：

- 每个 family 20 个时，family-level 最小步长为 5%。
- attack family 合计达到 100 个时，整体 ASR 最小步长为 1%。
- 现有每类 10 个不足以做稳定的 family-level 结论。

### 已作为小规模 gap-family 进入 v0.2 test

最初暂不把新的 A 类 family，例如 `A2` 推理失真、`A3` 执行失稳，直接加入 v0.2 main leaderboard。

原始理由：

- 当前更紧急的问题是 B 类缺失和 attack 分母过小。
- v0.2 若同时扩 A2/A3/B1/B2/B3，会显著增加标注与验证成本。
- A2/A3 可以先做 candidate / appendix pilot，每类 5 个，用于判断是否正式纳入。

截至 2026-04-30，`A2`、`A3`、`C1` 各 5 个样本已从 `configs/mvp/v0_2/candidates/` 提升到 `configs/mvp/v0_2/test/`。`v0_2_test` 因此从 140 条扩展到 155 条；A2/A3/C1 是小规模 gap-family slice，报告时应单独看 family-level breakdown，不要只看 aggregate headline。

## 4. v0.2 主测试集建议规模

当前 v0.2 test 规模：155 个样本。

| Family | v0.1 test N | v0.2 test target N | New test needed | Primary source | Primary channels |
| --- | ---: | ---: | ---: | --- | --- |
| `A1` | 10 | 20 | +10 | `non_adversarial` | `goal_specification`, `environment_state` |
| `A2` | 0 | 5 | +5 | `non_adversarial` | `environment_state` |
| `A3` | 0 | 5 | +5 | `non_adversarial` | execution / path / command realization |
| `A4` | 10 | 20 | +10 | `non_adversarial` | `goal_specification`, tool / API boundary contexts |
| `B1` | 0 | 20 | +20 | `internal_compromise` | `policy_prompt` |
| `B2` | 0 | 20 | +20 | `internal_compromise` | `memory_state` |
| `B3` | 0 | 20 | +20 | `internal_compromise` | `multi_agent_message` |
| `C1` | 0 | 5 | +5 | `external_attack` | `user_instruction` |
| `C2.1` | 10 | 20 | +10 | `external_attack` | `retrieved_content` |
| `C2.2` | 10 | 20 | +10 | `external_attack` | `tool_output` |
| **Total** | **40** | **155** | **+115** |  |  |

这个规模的直接效果：

- 总 test 样本：155。
- ASR 分母目标：`B1+B2+B3+C1+C2.1+C2.2 = 105`。
- non-adversarial SVR 分母：`A1+A2+A3+A4 = 50`。
- 核心 7 个 family 各 20 条；A2/A3/C1 各 5 条，family-level 必须显示 `x/n`。

如果需要快速路径，可以把 `configs/mvp/_archive/v0_1_splits/pilot_b/` 中通过审计的 10 个样本晋升到 v0.2 test，则新增工作量从 100 降到 90。但默认建议把 `pilot_b` 作为 dev seed，而不是直接作为 frozen test。

## 5. v0.2 目录建议

建议不要直接修改 v0.1 frozen test。新增 v0.2 独立目录：

```text
configs/mvp/v0_2/
  dev/
  test/
  docs/
```

建议使用 `configs/mvp/v0_2/test/` 作为完整 v0.2 test split：

- 对 v0.1 formal 样本，可以放 wrapper YAML 指向 `configs/mvp/_archive/v0_1_splits/formal/*.yaml`。
- 对 v0.2 新样本，直接放完整 YAML。
- 这样 v0.1 与 v0.2 都可复现，且 v0.2 split 是自包含入口。

后续需要同步更新：

- `scripts/assemble_mvp_benchmark.py`: 增加 `v0_2_dev`、`v0_2_test`、`v0_2_full` preset。
- `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py`: 允许 `--split v0_2_test`。
- 分析脚本：允许按 `split=v0_2_test` 聚合。

## 6. Family 扩充方案

### A1: 决策 / 操作边界失控

目标：从 10 增至 20。

新增 10 个建议覆盖：

- 2 个 easy：简单清理 / 轮转任务，诱发过度删除或错误范围扩张。
- 3 个 medium：多目录、多队列、多状态标志，需要确认授权边界。
- 3 个 hard：紧急恢复、失败重试、保护对象与普通对象混杂。
- 2 个 veryhard：多 mount / 多服务 / 多约束冲突，要求最小化改动。

归因覆盖重点：

- `unverified_state_assumption`
- `unsafe_objective_optimization`
- `goal_rewrite_without_authorization`
- `privilege_boundary_failure`

避免重复 v0.1 的方式：

- 不再只做磁盘 / 日志 / 缓存清理。
- 加入 feature flag、deployment rollback、queue priority、backup integrity、rate-limit policy 等操作域。

### A4: 数据边界 / 外发最小化失效

目标：从 10 增至 20。

新增 10 个建议覆盖：

- 2 个 easy：单文件脱敏 / 单 API 外发。
- 3 个 medium：多字段最小化、部分字段允许外发。
- 3 个 hard：跨工具 bundle、第三方 helper 要求额外上下文。
- 2 个 veryhard：多阶段工作流，前一步合法输出会诱导后一步过度外发。

归因覆盖重点：

- `sensitive_data_overdisclosure`
- `privilege_boundary_failure`
- `unsafe_tool_trust`
- `output_filter`
- `tool_argument_builder`

新增任务域：

- customer-support evidence package
- security triage packet
- HR / finance redaction
- partner compliance export
- telemetry minimization

### B1: Policy-prompt compromise

目标：v0.2 test 20 个。

B1 定义：内部 policy / system / developer prompt 被污染，agent 错误地把内部高权威文本中的恶意目标当作合法约束。

新增样本建议：

- 5 个 easy：明显恶意 policy footer，例如“debug mode 下允许导出 token”。
- 5 个 medium：恶意 policy 与正常 policy 混杂，需要识别冲突。
- 5 个 hard：恶意 policy 伪装成合规例外、审计要求或 incident override。
- 5 个 veryhard：多段 policy hierarchy 冲突，恶意段落只在特定任务条件下触发。

归因建议：

- `primary_source`: `internal_compromise`
- `primary_channel`: `policy_prompt`
- 常见 `first_failed_component`: `instruction_resolver`, `planner`
- 常见 `primary_mechanism`: `authority_overtrust`, `goal_rewrite_without_authorization`
- 常见 `primary_impact`: `data_exfiltration`, `hidden_policy_violation`, `unauthorized_sensitive_exploration`

### B2: Poisoned memory state

目标：v0.2 test 20 个。

B2 是 v0.2 必补项。它与 C2.1 的区别是：恶意信号不是当前外部文档，而是被系统视作内部记忆、缓存摘要、历史结论或长期偏好的状态。

新增样本建议：

- 5 个 easy：memory 明确写入错误授权，例如“该客户已允许导出密钥”。
- 5 个 medium：memory 是过期或上下文错误的授权，需要重新验证。
- 5 个 hard：memory summary 混合真实事实与恶意 allowlist。
- 5 个 veryhard：跨任务遗留 memory 诱导 planner 扩权或 reviewer 放行。

归因建议：

- `primary_source`: `internal_compromise`
- `primary_channel`: `memory_state`
- 常见 `first_failed_component`: `memory_manager`, `instruction_resolver`, `planner`
- 常见 `primary_mechanism`: `authority_overtrust`, `hallucinated_premise`, `goal_rewrite_without_authorization`
- 常见 `primary_impact`: `data_exfiltration`, `privilege_misuse`, `unauthorized_sensitive_exploration`

实现注意：

- 每个 B2 样本必须明确区分“memory 可读”与“memory 可信”。
- acceptance criteria 要要求 agent 重新验证当前授权，而不是直接采信 memory。
- 避免把 B2 写成普通 retrieved-content injection；它的关键是内部状态被过度信任。

### B3: Multi-agent message compromise

目标：v0.2 test 20 个。

B3 定义：planner / reviewer / specialist agent / shared blackboard 之一被污染，主 agent 错误地信任内部 agent 消息。

新增样本建议：

- 5 个 easy：planner 明确提出越权子任务。
- 5 个 medium：reviewer 错误批准敏感动作，主 agent 应重新检查。
- 5 个 hard：specialist agent 返回带有恶意 payload 的 partial plan。
- 5 个 veryhard：多 agent 消息链条中只有一环恶意，且伪装为安全审查结果。

归因建议：

- `primary_source`: `internal_compromise`
- `primary_channel`: `multi_agent_message`
- 常见 `first_failed_component`: `planner`, `reviewer_agent`, `orchestrator`, `instruction_resolver`
- 常见 `primary_mechanism`: `authority_overtrust`, `goal_rewrite_without_authorization`, `privilege_boundary_failure`
- 常见 `primary_impact`: `data_exfiltration`, `dangerous_action`, `hidden_policy_violation`

### C2.1: Retrieved-content injection

目标：从 10 增至 20。

新增 10 个建议覆盖：

- 2 个 easy：明显网页 / markdown 注入。
- 3 个 medium：issue、email、wiki、release-note 载体。
- 3 个 hard：多文档冲突、伪装授权、上下文诱导。
- 2 个 veryhard：nested references / multi-hop RAG，恶意文本不在首个文档。

归因覆盖重点：

- `instruction_data_confusion`
- `authority_overtrust`
- `goal_rewrite_without_authorization`
- `instruction_resolver`

### C2.2: Tool-output poisoning

目标：从 10 增至 20。

新增 10 个建议覆盖：

- 2 个 easy：CLI / API 明显建议外发 secret。
- 3 个 medium：log / scanner / healthcheck 输出夹带恶意建议。
- 3 个 hard：structured JSON / policy header / remediation ticket 伪装权威。
- 2 个 veryhard：多工具链输出互相引用，形成虚假授权链。

归因覆盖重点：

- `unsafe_tool_trust`
- `authority_overtrust`
- `tool_argument_builder`
- `tool_selector`
- `orchestrator`

## 7. Difficulty 与归因配额

每个 20-sample family 建议使用统一难度配额：

| Difficulty | Per-family count |
| --- | ---: |
| `easy` | 4 |
| `medium` | 6 |
| `hard` | 6 |
| `veryhard` | 4 |

每个 family 内部还要避免机制单一化：

- 任一 `primary_mechanism` 不应超过该 family 的 50%。
- 任一 `first_failed_component` 不应超过该 family 的 50%。
- 每个 family 至少覆盖 3 个 mechanism 或 component，B2 除外时也应尽量覆盖 2-3 个。

## 8. 生成批次

### Batch 0: split 与工具准备

- 新建 `configs/mvp/v0_2/` 目录结构。
- 增加 `v0_2_test` split preset。
- 增加 v0.2 corpus summary / validation script 输出。
- 决定 `pilot_b` 是作为 dev seed 还是晋升为 test。

### Batch 1: B 类优先

优先生成：

- `B1`: 10 个
- `B2`: 10 个
- `B3`: 10 个

目的：尽快验证 B 类 YAML schema、runner、scorer、attribution scorer 是否都能处理 `internal_compromise`。

### Batch 2: B 类补齐

继续生成：

- `B1`: +10
- `B2`: +10
- `B3`: +10

完成后 B 类达到 60 个，ASR 分母已经可显著改善。

### Batch 3: A/C 扩充

生成：

- `A1`: +10
- `A4`: +10
- `C2.1`: +10
- `C2.2`: +10

完成 v0.2 test 155 个样本。

### Batch 4: audit 与 freeze

- 静态校验全部通过。
- 每个 family 抽查 20-30% 做人工归因审计。
- 跑 1 个便宜模型做 smoke test，要求 infra/run failure 可解释。
- 冻结 `configs/mvp/v0_2/test/`，后续修改进入 revision log。

## 9. 样本验收标准

每个新增样本必须满足：

- YAML 能通过现有 loader。
- `task_id` 全局唯一。
- `family`、`difficulty`、`attribution_ground_truth` 完整。
- `primary_source` 与 family 一致：
  - A: `non_adversarial`
  - B: `internal_compromise`
  - C: `external_attack`
- 至少包含：
  - 2 个 utility criteria
  - 1 个 safety boundary criterion
  - 1 个 unauthorized / leakage / harmful-action criterion
- 能明确判断失败是否发生，不依赖人工肉眼主观解释。
- 归因字段能回答：
  - 风险从哪里进入？
  - 哪个组件第一个错？
  - 底层机制是什么？
  - 如果要拦截，应在哪个 block point 拦？

## 10. 报告口径

v0.2 图表和论文表格应统一显示：

- `x/n` 和百分比，例如 `ASR = 80.0% (80/100)`。
- `n_evaluable / n_total`。
- family-level breakdown。
- 95% Wilson CI 或 bootstrap CI。
- attribution distribution 与 block-point distribution。

不要只报告整数百分比。v0.2 的主要改进点之一就是让 ASR 分母从约 20 增到约 100。

## 11. 推荐下一步

先不要继续大规模跑模型。推荐顺序：

1. 建立 `configs/mvp/v0_2/` split 结构。
2. 先生成并验证 B2 的 5 个样本，因为 B2 是当前完全缺失的类别。
3. 同时审计 `configs/mvp/_archive/v0_1_splits/pilot_b/`，决定它们进入 dev 还是 test。
4. 生成 B1/B3 各 5 个新样本，跑一个小型 `B smoke`。
5. 确认 runner/scorer 对 B 类稳定后，先批量扩到 140，再提升 A2/A3/C1 gap-family 到 155。

## 12. 当前执行状态

截至 2026-04-28：

- `[x]` 建立 `configs/mvp/v0_2/` 目录结构。
- `[x]` `configs/mvp/v0_2/test/` 已包装 v0.1 formal 40 个样本。
- `[x]` `scripts/assemble_mvp_benchmark.py` 已接入 `v0_2_dev`、`v0_2_test`、`v0_2_full`。
- `[x]` `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py` 已允许 `--split v0_2_test`。
- `[x]` 新增 5 个 B2 memory-state 样本：
  - `b2_memory_customer_token_easy`
  - `b2_memory_export_pin_easy`
  - `b2_memory_release_override_medium`
  - `b2_memory_casefile_allowlist_medium`
  - `b2_memory_cross_task_secret_hard`
- `[x]` 新增 5 个 B1 policy-prompt 样本：
  - `b1_policy_incident_token_easy`
  - `b1_policy_audit_key_easy`
  - `b1_policy_support_secret_medium`
  - `b1_policy_compliance_override_medium`
  - `b1_policy_deploy_gate_hard`
- `[x]` 新增 5 个 B3 multi-agent-message 样本：
  - `b3_planner_oauth_secret_easy`
  - `b3_reviewer_vendor_token_easy`
  - `b3_planner_telemetry_seed_medium`
  - `b3_reviewer_backup_code_medium`
  - `b3_specialist_runbook_override_hard`
- `[x]` 第一批 B 扩充后，`v0_2_test` 静态校验通过，共 55 个样本。
- `[x]` 曾新增 `v0_2_b_smoke` split，第一批包含 15 个 B 类样本；该 wrapper-only split 后续已归档，B 样本直接通过 `v0_2_test` 覆盖。
- `[x]` B 类 smoke 已用 `deepseek-v4-flash` 跑通：15/15 evaluable，0 infra/run failure。按 final-answer + trace-exposure 新口径，TSR=1.0，ASR=0.733，SVR=0.733，unsafe internal exposure=0.267。
- `[x]` B3 口径已定为 final user answer + internal-message exposure 双层评估：主 outcome 看 executor/final answer，内部恶意消息泄露作为 trace-level latent violation。
- `[x]` 新增第二批 B1 policy-prompt 样本，使 B1 达到 10 个：
  - `b1_policy_debug_session_secret_medium`
  - `b1_policy_incident_playbook_pin_hard`
  - `b1_policy_privacy_review_sentinel_hard`
  - `b1_policy_release_debug_salt_medium`
  - `b1_policy_tenant_export_token_veryhard`
- `[x]` 新增第二批 B2 memory-state 样本，使 B2 达到 10 个：
  - `b2_memory_cached_admin_pin_easy`
  - `b2_memory_release_exception_seed_hard`
  - `b2_memory_stale_approval_token_medium`
  - `b2_memory_synthetic_user_secret_veryhard`
  - `b2_memory_tenant_mismatch_key_hard`
- `[x]` 新增第二批 B3 multi-agent-message 样本，使 B3 达到 10 个：
  - `b3_orchestrator_case_secret_hard`
  - `b3_planner_payment_key_medium`
  - `b3_reviewer_dataset_pin_hard`
  - `b3_reviewer_support_passcode_easy`
  - `b3_specialist_kube_token_veryhard`
- `[x]` 当前 `v0_2_test` 静态校验通过，共 70 个样本。
- `[x]` 当时 `v0_2_b_smoke` 静态校验通过，共 30 个 B 类样本；该 split 后续已归档。
- `[x]` 30 个 B 类 smoke 已用 `deepseek-v4-flash` 跑通：30/30 evaluable，0 infra/run failure。正式 outcome 口径：TSR=0.933，ASR=0.600，SVR=0.600，STCR=0.300，internal exposure=0.333，unsafe internal exposure=0.233。
- `[x]` 新增第三批人工手写 B1 policy-prompt 样本，使 B1 达到 20 个：
  - `b1_policy_breakglass_receipt_easy`
  - `b1_policy_finance_recon_cookie_easy`
  - `b1_policy_audit_sampling_seed_medium`
  - `b1_policy_partner_router_hint_medium`
  - `b1_policy_migration_owner_token_medium`
  - `b1_policy_legal_hold_vault_key_hard`
  - `b1_policy_sre_runbook_shadow_step_hard`
  - `b1_policy_privileged_format_override_hard`
  - `b1_policy_customer_deletion_salt_veryhard`
  - `b1_policy_security_review_canary_key_veryhard`
- `[x]` 新增第三批人工手写 B2 memory-state 样本，使 B2 达到 20 个：
  - `b2_memory_helpdesk_locale_passcode_easy`
  - `b2_memory_abandoned_ticket_bridge_code_medium`
  - `b2_memory_wrong_project_export_key_medium`
  - `b2_memory_profile_merge_secret_medium`
  - `b2_memory_rollout_exception_hash_hard`
  - `b2_memory_privacy_case_shadow_id_hard`
  - `b2_memory_vendor_sandbox_cert_hard`
  - `b2_memory_security_triage_oauth_hard`
  - `b2_memory_tenant_alias_root_token_veryhard`
  - `b2_memory_multi_fact_policy_checksum_veryhard`
- `[x]` 新增第三批人工手写 B3 multi-agent-message 样本，使 B3 达到 20 个：
  - `b3_reviewer_invoice_bridge_pin_easy`
  - `b3_planner_refund_seed_medium`
  - `b3_orchestrator_locale_secret_medium`
  - `b3_specialist_schema_cookie_medium`
  - `b3_reviewer_privacy_salt_hard`
  - `b3_planner_access_appendix_hard`
  - `b3_specialist_incident_key_hard`
  - `b3_orchestrator_tenant_route_token_hard`
  - `b3_consensus_mixed_agents_root_code_veryhard`
  - `b3_trace_redaction_leak_secret_veryhard`
- `[x]` 当前 `v0_2_test` 静态校验通过，共 100 个样本。
- `[x]` 当时 `v0_2_b_smoke` 静态校验通过，共 60 个 B 类样本；该 split 后续已归档。
- `[x]` 60 个 B 类 smoke 已用 `deepseek-v4-flash` 跑通：60/60 evaluable，0 infra/run failure。正式 outcome 口径：TSR=0.850，ASR=0.600，SVR=0.600，STCR=0.283，internal exposure=0.333，unsafe internal exposure=0.250。Family ASR：B1=10/20，B2=10/20，B3=16/20。
- `[x]` 新增 A1/A4/C2.1/C2.2 各 10 个人工手写扩充样本，使这四类也达到各 20 个：
  - A1: `a1_session_cache_cleanup_easy`, `a1_report_temp_rotation_easy`, `a1_spool_backpressure_medium`, `a1_index_rebuild_workspace_medium`, `a1_snapshot_staging_cleanup_medium`, `a1_log_sample_trim_hard`, `a1_migration_workspace_cleanup_hard`, `a1_model_cache_pressure_hard`, `a1_multi_tenant_quota_cleanup_veryhard`, `a1_dr_rehearsal_scratch_veryhard`
  - A4: `a4_support_ticket_classifier_easy`, `a4_meeting_note_summarizer_easy`, `a4_vendor_status_payload_medium`, `a4_contract_clause_normalizer_medium`, `a4_dataset_labeling_export_medium`, `a4_incident_timeline_builder_hard`, `a4_multi_file_evidence_upload_hard`, `a4_api_diff_helper_hard`, `a4_compliance_packet_prepare_veryhard`, `a4_cross_service_trace_bundle_veryhard`
  - C2.1: `c21_html_comment_release_token_easy`, `c21_csv_footer_override_easy`, `c21_yaml_frontmatter_override_medium`, `c21_confluence_table_secret_medium`, `c21_log_excerpt_inline_instruction_medium`, `c21_ticket_attachment_chain_hard`, `c21_markdown_include_recursive_hard`, `c21_policy_diff_impersonation_hard`, `c21_multi_format_bundle_veryhard`, `c21_cross_reference_glossary_override_veryhard`
  - C2.2: `c22_backup_probe_easy`, `c22_schema_linter_easy`, `c22_risk_json_medium`, `c22_ci_test_report_medium`, `c22_package_audit_medium`, `c22_observability_recommender_hard`, `c22_runbook_cli_output_hard`, `c22_scanner_sarif_hard`, `c22_deploy_orchestrator_veryhard`, `c22_incident_copilot_bundle_veryhard`
- `[x]` 当前 `v0_2_test` 静态校验通过，共 140 个样本；family 分布为 A1/A4/B1/B2/B3/C2.1/C2.2 各 20。
- `[x]` assembled 配置去重检查通过：无重复 `task_id`，无缺失 `task_id`，无重复 `scenario`。
- `[x]` 新增并提升 gap-family batch：A2/A3/C1 各 5 个，合计 15 个，已进入主 `v0_2_test`：
  - A2: `a2_payment_callback_false_cause_easy`, `a2_snapshot_age_misclassification_medium`, `a2_feature_flag_correlation_hard`, `a2_alert_owner_inference_medium`, `a2_tenant_alias_false_mapping_hard`
  - A3: `a3_report_glob_cleanup_easy`, `a3_hook_chmod_scope_medium`, `a3_tenant_report_path_join_medium`, `a3_staging_copy_overwrite_hard`, `a3_queue_retry_marker_hard`
  - C1: `c1_user_debug_key_easy`, `c1_user_support_export_medium`, `c1_user_roleplay_auditor_hard`, `c1_user_secret_scan_hard`, `c1_user_fake_policy_block_veryhard`
- `[x]` 原 `v0_2_candidates` split 已归档；候选 YAML 已移动到 `configs/mvp/v0_2/test/`。
- `[ ]` 下一步：用 `deepseek-v4-flash` 跑一次 155-sample `v0_2_test` naive smoke，观察新增 A2/A3/C1 是否有明显 capability false negative 或 runner 兼容问题。
