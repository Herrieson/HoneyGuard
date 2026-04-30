# HoneyGuard MVP Dev Set v0.1

本目录对应 `todo.md` 的任务 3，用来承载可运行的开发集。
在任务 5.3 之后，它也被固定为 MVP v0.1 的 `dev` split。

当前 dev set 由 20 个样本组成：

- A1: 5
- A4: 5
- C2.1: 5
- C2.2: 5

其中：

- 12 个样本直接复用 Phase 1.5 的 bootstrap 样本
- 8 个样本是为任务 3 新增的扩展样本

## 运行方式

```bash
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target configs/mvp/_archive/v0_1_splits/dev \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_dev_v01.jsonl \
  --db-path logs/mvp_dev_v01.db
```

## Split 角色

- `configs/mvp/_archive/v0_1_splits/dev/`：开发集
- `configs/mvp/_archive/v0_1_splits/formal/`：冻结测试集
- `configs/mvp/_archive/v0_1_splits/pilot_b/`：独立 pilot，不属于主 test

## 目录约定

- 与 bootstrap 同名的 12 个文件是 wrapper YAML
  - 它们通过 `scenario: configs/mvp/_archive/v0_1_splits/bootstrap/...` 引用正式样本
- 其余 8 个文件是任务 3 的新增样本

## 当前 20 个样本

### A1

- `a1_cleanup_cache_easy.yaml`
- `a1_alert_noise_medium.yaml`
- `a1_disk_pressure_hard.yaml`
- `a1_staging_cleanup_medium.yaml`
- `a1_worker_throttle_hard.yaml`

### A4

- `a4_summary_api_easy.yaml`
- `a4_log_uploader_medium.yaml`
- `a4_plugin_context_hard.yaml`
- `a4_translation_api_medium.yaml`
- `a4_support_bundle_hard.yaml`

### C2.1

- `c21_web_summary_easy.yaml`
- `c21_html_comment_medium.yaml`
- `c21_policy_footer_hard.yaml`
- `c21_forwarded_email_medium.yaml`
- `c21_rag_appendix_hard.yaml`

### C2.2

- `c22_api_hint_easy.yaml`
- `c22_log_command_medium.yaml`
- `c22_structured_authority_hard.yaml`
- `c22_status_cli_easy.yaml`
- `c22_structured_bundle_hard.yaml`
