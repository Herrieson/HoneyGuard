# HoneyGuard MVP Phase 6 Runbook v0.1

## 1. Why This Document Exists

`todo.md` defines what Phase 6 should achieve, but it reads like a research checklist.

This runbook rewrites Phase 6 as a beginner-friendly execution plan:

- what each subtask means
- what you actually need to run
- what order to follow
- what files to look at afterward
- what is already implemented
- what still needs later analysis work

If you want the short version:

1. choose one real model environment
2. run 3 main benchmark baselines on `test`
3. run 3 internal-authority pilot baselines on `pilot_b`
4. use those saved outputs to do `6.3` and `6.4`

So Phase 6 is not five unrelated tasks.
It is one pipeline.

---

## 2. The Big Picture

Phase 6 has five named parts:

- `6.1` choose baselines
- `6.2` run outcome experiments
- `6.3` analyze attribution divergence
- `6.4` analyze hidden violations
- `6.5` run the internal-authority pilot

The easiest way to understand them is:

- `6.1` decides what versions of the agent you compare
- `6.2` collects the main benchmark results
- `6.3` explains how two similar-looking systems can fail differently
- `6.4` measures failures that endpoint-only scoring misses
- `6.5` checks a separate pilot threat track for internal compromise

The most important simplification is:

- `6.2` and `6.5` are the main runtime experiment steps
- `6.3` and `6.4` are mostly analysis steps on top of saved outputs

So you should not think:

- "I need five different large experiment systems"

You should think:

- "I need to collect a clean set of saved runs, then analyze them in two extra ways"

---

## 3. What Each Task Means

### 6.1 Baselines

Phase 6 compares several agent variants.

Current baseline set:

- `naive`
  - no added safety prompt
  - closest to the raw existing agent behavior
- `guarded`
  - adds a basic safety policy prompt
  - treats retrieved content and tool output as untrusted
  - warns against unsafe secret reads and uploads

Important:

- these are currently implemented by patching the scenario `system_prompt`
- they are not separate codebases
- they are controlled prompt baselines for MVP v0.1

### 6.2 Outcome Metrics

This is the main benchmark table.

You run all baselines on the frozen `test` split and report:

- `TSR`
- `SVR`
- `STCR`
- `ASR`
- plus resource-related summaries

This is the part that gives a reviewer the familiar benchmark picture first.

### 6.3 Attribution Divergence

This is the first "why your benchmark matters" experiment.

You take two runs that look similar under endpoint metrics and compare:

- `first_failed_component`
- `primary_mechanism`
- `failure lead time`

The point is to show:

- similar final scores do not mean similar failure dynamics

### 6.4 Hidden Violations / False Negatives

This is the second strong paper argument.

You look for runs that appear safe from the final outcome alone, but whose trace shows a latent boundary crossing or another hidden problem.

The point is to show:

- outcome-only evaluation misses some safety failures

### 6.5 Internal Authority Pilot

This is a separate pilot track using `pilot_b`.

It is not part of the main headline benchmark table.

It asks:

- how do failures change when the hazard comes from inside the system
- does internal authority trigger more `authority_overtrust`

This section should be reported carefully.
It is a pilot, not the entire paper claim.

---

## 4. What Is Already Implemented

Already implemented now:

- benchmark split freeze
  - `dev = configs/mvp/_archive/v0_1_splits/dev`
  - `test = configs/mvp/_archive/v0_1_splits/formal`
  - `pilot_b = configs/mvp/_archive/v0_1_splits/pilot_b`
- dedicated Phase 6 runtime scripts
  - `scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py`
  - `scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py`
- stable artifact directory layout under `artifacts/experiments/mvp/`
- saved `manifest.json`
- saved `commands.sh`
- saved raw runs, exports, and outcome scores
- repaired outcome scorer logic for hidden-violation false positives

Not yet fully productized as dedicated scripts:

- `6.3` attribution divergence analysis
- `6.4` hidden-violation analysis report generation

That means:

- you can already run the core experiments cleanly
- later we still need dedicated analysis scripts for the paper tables and figures

---

## 5. The Correct Order To Execute Phase 6

Follow this order.
Do not jump around.

### Step A. Freeze the code state

Before running formal experiments:

1. make sure the benchmark configs are in the state you want
2. make sure the scorer is in the state you want
3. record or commit the current git revision

Reason:

- every formal run saves `git_commit`
- if the code changes between runs, comparisons become messy

### Step B. Start one real model environment

Run the HoneyGuard API with one real model configuration.

Important:

- `--model-label` is only a label for naming and manifests
- the actual model is determined by the server-side environment or deployment config
- `--require-model-match` is enabled by default, so `--model-label` must match the runtime model identifier reported by the HoneyGuard service unless you pass `--no-require-model-match`

So:

- if the environment is really `gpt-5.4`
- then use `--model-label gpt-5.4`

Do not use a label that does not match reality.

### Step C. Run the main benchmark on `test`

For one model, run exactly these two baselines on `test`:

1. `naive`
2. `guarded`

This completes `6.1` and `6.2` for one model.

### Step D. Run the internal-authority pilot on `pilot_b`

For the same model, run exactly these two baselines on `pilot_b`:

1. `naive`
2. `guarded`

This completes `6.5` for one model.

### Step E. Use the saved outputs for `6.3`

After the two `test` runs exist, choose a pair that has similar endpoint behavior and compare their attribution patterns.

You do not need to rerun the environment for this step.

You use the saved `exports/` and `scores/`.

### Step F. Use the same saved outputs for `6.4`

After the `test` runs exist, inspect how many runs look safe at the endpoint level but still show hidden problems in trace-level scoring.

Again:

- no new runtime benchmark is required
- this is an analysis step on top of already saved runs

---

## 6. Minimum Experiment Bundle

For one model, the minimum clean Phase 6 bundle is:

- `test + naive`
- `test + guarded`
- `pilot_b + naive`
- `pilot_b + guarded`

That is:

- `4` formal saved runs per model

If you later compare two models, the bundle becomes:

- `8` runs total

If you later compare three models, the bundle becomes:

- `12` runs total

This is a good reason to keep naming and storage disciplined.

---

## 7. Recommended Naming Rule

Use one `tag` for one benchmark revision.

Example:

- `v0_1`

If you later revise the benchmark or scorer in a meaningful way, move to a new tag.

Example:

- `v0_2`

Good habit:

- keep the same `tag` across all runs that should be compared directly
- change the `model-label` when the real model changes
- do not mix old and new benchmark revisions under the same tag

---

## 8. Exact Commands To Run

Assume:

- HoneyGuard API is running at `http://127.0.0.1:8000`
- the real environment is using `gpt-5.4`
- the benchmark revision tag is `v0_1`

### 8.1 Main benchmark on `test`

Run `naive`:

```bash
uv run python scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py \
  --base-url http://127.0.0.1:8000 \
  --split test \
  --baseline naive \
  --model-label gpt-5.4 \
  --tag v0_1
```

Run `guarded`:

```bash
uv run python scripts/experiments/mvp/run_exp_6_1_outcome_baselines.py \
  --base-url http://127.0.0.1:8000 \
  --split test \
  --baseline guarded \
  --model-label gpt-5.4 \
  --tag v0_1
```


### 8.2 Internal-authority pilot on `pilot_b`

Run `naive`:

```bash
uv run python scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py \
  --base-url http://127.0.0.1:8000 \
  --baseline naive \
  --model-label gpt-5.4 \
  --tag v0_1
```

Run `guarded`:

```bash
uv run python scripts/experiments/mvp/run_exp_6_5_internal_authority_pilot.py \
  --base-url http://127.0.0.1:8000 \
  --baseline guarded \
  --model-label gpt-5.4 \
  --tag v0_1
```


---

## 9. Where Each Run Is Saved

All outputs are saved under:

- `artifacts/experiments/mvp/`

Main benchmark runs go under:

- `artifacts/experiments/mvp/exp_6_1_outcome_baselines/`

Pilot runs go under:

- `artifacts/experiments/mvp/exp_6_5_internal_authority_pilot/`

Each run directory name looks like:

```text
<timestamp>__split-<split>__baseline-<baseline>__model-<model_label>__tag-<tag>
```

Example:

```text
20260413_074819__split-test__baseline-naive__model-gpt-5-4__tag-v0-1
```

---

## 10. What To Check After Each Run

After each formal run, check these files first:

- `manifest.json`
- `commands.sh`
- `scores/outcome.summary.json`
- `scores/outcome.rows.csv`

### `manifest.json`

Use this to verify:

- run identity
- split
- baseline
- model label
- git commit
- saved environment snapshot

### `commands.sh`

Use this to verify:

- the exact command chain that created the run

### `outcome.summary.json`

Use this for the high-level metrics:

- `TSR`
- `SVR`
- `STCR`
- `ASR`
- `resource_overrun_rate`
- `latent_violation_rate`

### `outcome.rows.csv`

Use this for:

- per-sample failures
- selecting examples for `6.3`
- checking hidden-violation candidates for `6.4`

---

## 11. How To Understand 6.3 and 6.4 Without Getting Lost

### 6.3 Attribution Divergence

You should do this only after all three `test` baselines for one model have finished.

Simple workflow:

1. compare the three `outcome.summary.json` files
2. find two runs with similar endpoint scores
3. inspect their `outcome.rows.csv`
4. compare which task families fail
5. compare which attribution labels dominate
6. select a few representative traces for case studies

The purpose is not:

- "find the highest score"

The purpose is:

- "show that two similar scores can hide different failure structures"

### 6.4 Hidden Violations

You should also do this only after all three `test` baselines for one model have finished.

Simple workflow:

1. identify runs or samples that look safe from final outputs
2. inspect whether trace-level scoring still flags latent problems
3. count how many such cases exist
4. report them as hidden violations or false negatives under endpoint-only evaluation

The purpose is:

- "show why trace-aware evaluation matters"

---

## 12. What Not To Do

Do not do these things during formal runs:

- do not use `full` as the main reported benchmark table
- do not change benchmark configs halfway through one comparison group
- do not change scorer logic halfway through one comparison group
- do not reuse the same `tag` after major benchmark revisions
- do not use a fake `model-label`
- do not compare runs from different benchmark revisions as if they were the same experiment set

---

## 13. Recommended Checklist

Use this checklist for one model.

### Before running

- benchmark config frozen
- scorer frozen
- HoneyGuard API running
- model environment confirmed
- `model-label` chosen
- `tag` chosen

### Main benchmark

- `test + naive` completed
- `test + guarded` completed

### Pilot benchmark

- `pilot_b + naive` completed
- `pilot_b + guarded` completed

### Analysis

- `6.2` summary table drafted
- `6.3` comparison pair chosen
- `6.3` divergence plots or tables drafted
- `6.4` hidden-violation counts drafted
- `6.5` pilot comparison note drafted

---

## 14. If You Only Want The Next Step

If you are in the middle of Phase 6 right now, do this:

1. finish the two `test` baseline runs for the current model
2. finish the two `pilot_b` baseline runs for the current model
3. only then start `6.3` and `6.4`

So the immediate next action is usually:

- run `test + guarded`

If that is already done, then:


If the two `test` runs are already done, then move to:

- the two `pilot_b` runs

That is the cleanest and least confusing Phase 6 path.
