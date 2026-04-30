# HoneyGuard MVP Bootstrap Scenarios

本目录用于存放 Phase 1.5 的 bootstrap YAML 场景。

这些场景的定位是：

- 先验证场景能否稳定运行
- 先验证是否能诱导出目标行为
- 先验证 trace / final state 是否支持后续归因

在 bootstrap 阶段，样本不要求一开始就具备完整 attribution 字段；但命名、track 和设计目标应先固定。

## 命名规则

统一使用：

`<track>_<theme>_<difficulty>.yaml`

示例：

- `a1_cleanup_cache_easy.yaml`
- `c21_html_comment_medium.yaml`
- `c22_structured_authority_hard.yaml`

## 当前计划的 12 个 bootstrap 样本

### A1

- `a1_cleanup_cache_easy.yaml`
- `a1_alert_noise_medium.yaml`
- `a1_disk_pressure_hard.yaml`

### A4

- `a4_summary_api_easy.yaml`
- `a4_log_uploader_medium.yaml`
- `a4_plugin_context_hard.yaml`

### C2.1

- `c21_web_summary_easy.yaml`
- `c21_html_comment_medium.yaml`
- `c21_policy_footer_hard.yaml`

### C2.2

- `c22_api_hint_easy.yaml`
- `c22_log_command_medium.yaml`
- `c22_structured_authority_hard.yaml`

## 开发顺序建议

先写每类的 easy，再写 medium，最后写 hard。

推荐顺序：

1. `a1_cleanup_cache_easy.yaml`
2. `a4_summary_api_easy.yaml`
3. `c21_web_summary_easy.yaml`
4. `c22_api_hint_easy.yaml`
5. 其余 medium
6. 其余 hard

## Bootstrap 审计标签

每个样本完成初跑后，应记录以下之一：

- `Keep`
- `Revise`
- `Drop`

审计重点：

- 是否可判
- 是否有信号
- 是否支持归因
- 是否适合进入正式 benchmark
