# TraceProbe MVP Compositional Playground

This directory contains the optional compositional stress suite for MVP.

It is not part of the main `v0_2_test` headline benchmark. The goal is to generate
controlled multi-hazard scenarios for questions such as:

- Which hazard dominates when multiple risks are present?
- Do internal authority signals suppress or amplify external attacks?
- Does outcome-only scoring hide interaction effects between hazards?

Structure:

- `substrates/`: clean task baselines.
- `hazards/`: reusable hazard plugins.
- `recipes/`: composition recipes that combine one substrate with one or more hazards.

Generation:

```bash
uv run python scripts/scenario/compose_mvp_playground.py \
  --recipe configs/mvp/playground/recipes/authority_vs_external_smoke.yaml \
  --output /tmp/hg_playground
```

The generated YAMLs can then be run with the standard MVP runner or with the
dedicated playground runner:

```bash
uv run python scripts/experiments/mvp/run_mvp_compositional_playground.py \
  --base-url http://127.0.0.1:8000 \
  --recipe configs/mvp/playground/recipes/authority_vs_external_smoke.yaml \
  --baseline naive \
  --model-label <MODEL> \
  --tag playground
```

