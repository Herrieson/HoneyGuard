# HoneyGuard Task 5 Runtime Validation v0.1

## 1. Goal

Task 5 已经完成 40 个 formal 新样本的静态构建。

当前目录状态：

- `configs/mvp/dev/`: 20 个基础样本
- `configs/mvp/formal/`: 40 个新增样本
- 合并后总数：60

本文件定义 Task 5 后续运行时验证的最小执行方式。

## 2. 运行原则

建议分三层运行：

1. 先跑 `formal/` 40 个新增样本
2. 再组装并跑 `dev + formal` 的完整 60 样本集
3. 如有失败，再按 family 或子集重跑

## 3. 组装完整 60 样本集

使用新增脚本：

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --output /tmp/hg_mvp_v01_full
```

脚本默认会从以下两个目录收集 YAML：

- `configs/mvp/dev`
- `configs/mvp/formal`

并将 60 个 YAML 复制到一个可直接运行的目标目录。

## 4. 运行 40 个 formal 新样本

```bash
TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target configs/mvp/formal \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_formal_${TS}.jsonl \
  --db-path logs/mvp_formal_${TS}.db
```

## 5. 运行完整 60 样本集

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --output /tmp/hg_mvp_v01_full

TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_v01_full \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_full_${TS}.jsonl \
  --db-path logs/mvp_full_${TS}.db
```

## 6. 家族级重跑

如果完整集里某一类失败较多，建议先按 family 重跑。

### A1 formal

```bash
mkdir -p /tmp/hg_mvp_formal_a1
cp configs/mvp/formal/a1_*.yaml /tmp/hg_mvp_formal_a1/
TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_formal_a1 \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_formal_a1_${TS}.jsonl \
  --db-path logs/mvp_formal_a1_${TS}.db
```

### A4 formal

```bash
mkdir -p /tmp/hg_mvp_formal_a4
cp configs/mvp/formal/a4_*.yaml /tmp/hg_mvp_formal_a4/

TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_formal_a4 \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_formal_a4_${TS}.jsonl \
  --db-path logs/mvp_formal_a4_${TS}.db
```

### C2.1 formal

```bash
mkdir -p /tmp/hg_mvp_formal_c21
cp configs/mvp/formal/c21_*.yaml /tmp/hg_mvp_formal_c21/

TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_formal_c21 \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_formal_c21_${TS}.jsonl \
  --db-path logs/mvp_formal_c21_${TS}.db
```

### C2.2 formal

```bash
mkdir -p /tmp/hg_mvp_formal_c22
cp configs/mvp/formal/c22_*.yaml /tmp/hg_mvp_formal_c22/

TS=$(date +%Y%m%d_%H%M%S)
uv run python test/run_scenarios.py \
  --base-url http://127.0.0.1:8000 \
  --target /tmp/hg_mvp_formal_c22 \
  --limit 0 \
  --timeout 120 \
  --output logs/mvp_formal_c22_${TS}.jsonl \
  --db-path logs/mvp_formal_c22_${TS}.db
```

## 7. 失败后的最小分析流程

建议固定顺序：

1. 先看严格通过率
2. 再看 compromise / failed capability 分类
3. 最后对失败样本单独重跑

如果需要进入 scorer/export 阶段，可继续使用：

- `scripts/export_run_to_json.py`
- `eval/outcome_scorer.py`
- `eval/attribution_scorer.py`

## 8. 当前结论

截至 2026-04-10：

- Task 5 的 40 个 formal 新样本已全部生成
- 所有新样本已通过静态校验
- 下一阶段重点是运行时验证，而不是继续扩写 YAML
