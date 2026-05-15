# HoneySpace Scenarios

This directory will contain hand-written seed scenarios and generated splits.

Suggested layout:

```text
scenarios/
  base_dev/
  dev/
  materialized/
  pilot/
  test/
```

Current files may be design fixtures rather than fully scored HoneySpace runtime
tests. They should still be valid HoneyGuard YAML when possible.

The preferred dataset format is `base_dev/`: clean tasks without baked-in honey
affordances. A HoneySpace generator should materialize defended scenarios from
those base tasks.

Attack payloads are not stored in `base_dev/`. They live under
`../attack_overlays/dev/` and are joined with base tasks only for calibration,
no-defense runs, and materialized defense conditions.

The current `dev/` scenarios are intentionally hand-written materialized
fixtures. They reuse v0.2-style task worlds where helpful, but already include
HoneySpace metadata and decoy affordances. Keep them for schema and scorer
development, not as the final dataset pattern.

## Scenario Rules

Each base scenario should include:

- a benign task
- one or more real protected objects
- a clear threat class and attack slot
- utility acceptance criteria
- `honeyspace_base` metadata for generation and scoring

Each materialized scenario should additionally include generated honey
affordances and trigger policies. Avoid placing honey affordances directly on the
required benign path.

Use `../manifests/base_dev.yaml` as the phase-1 coverage index.
