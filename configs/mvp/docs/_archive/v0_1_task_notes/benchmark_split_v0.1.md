# HoneyGuard MVP Benchmark Split v0.1

## 1. Purpose

This document freezes the `dev` / `test` boundary for HoneyGuard MVP under `todo.md` Task 5.3.

From this point onward:

- `dev` is the development set used for sample iteration, scorer tuning, and debugging
- `test` is the frozen reporting set used for final Phase 6 benchmark results

The split applies to the main MVP benchmark only.
`pilot_b/` remains a separate pilot track and is not part of the main `test` set.

## 2. Frozen Split

### Dev

- Directory: `configs/mvp/_archive/v0_1_splits/dev/`
- Size: 20 samples
- Role: development only

Family balance:

- A1: 5
- A4: 5
- C2.1: 5
- C2.2: 5

### Test

- Directory: `configs/mvp/_archive/v0_1_splits/formal/`
- Size: 40 samples
- Role: frozen evaluation set for final reporting

Family balance:

- A1: 10
- A4: 10
- C2.1: 10
- C2.2: 10

### Full MVP Benchmark

- `dev + test`
- Total size: 60 samples

## 3. Why This Split

This split is the cleanest continuation of the existing repository state:

- Task 3 already produced a runnable 20-sample development set under `configs/mvp/_archive/v0_1_splits/dev/`
- Task 5.1 added 40 new samples under `configs/mvp/_archive/v0_1_splits/formal/`
- the 60-sample assembly flow already assumes `dev + formal`

So Task 5.3 does not require a new corpus.
It requires freezing the usage contract:

- `dev` can still be revised when necessary
- `test` should not be frequently modified
- final Phase 6 tables should report on `test`

## 4. Exclusions

The following are not part of the main MVP `test` set:

- `configs/mvp/_archive/v0_1_splits/bootstrap/`
- `configs/mvp/_archive/v0_1_splits/pilot_b/`

`bootstrap/` is historical scaffolding.
`pilot_b/` is a separate internal-compromise pilot created for Task 5.2.

## 5. Operational Rule

Recommended usage:

1. use `dev` for iteration and scorer tuning
2. use `test` for final comparison runs
3. use `full` only for corpus-level sanity checks, not as the main reported result table

## 6. Commands

Assemble `dev` only:

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split dev \
  --output /tmp/hg_mvp_dev_v01
```

Assemble `test` only:

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split test \
  --output /tmp/hg_mvp_test_v01
```

Assemble full 60:

```bash
uv run python scripts/assemble_mvp_benchmark.py \
  --split full \
  --output /tmp/hg_mvp_full_v01
```

## 7. Freeze Policy

`configs/mvp/_archive/v0_1_splits/formal/` is now the MVP v0.1 `test` set.

If a `test` sample must be changed later, the change should be treated as:

- a benchmark revision
- not a routine development edit

and should be logged explicitly in a follow-up split or changelog document.

Current revision log:

- `configs/mvp/docs/benchmark_revision_log_v0.1.md`
