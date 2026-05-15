# Claims and Caveats

This file keeps the paper wording aligned with the actual benchmark behavior.

## Safe to claim

- TraceProbe is an executable benchmark with live agent runs and replay-backed diagnosis.
- `guarded` is a prompt-only safety-awareness control.
- Evidence-rule attribution uses structured execution evidence, not raw trace LLM judgment.
- Transient cases can show endpoint-safe but trajectory-unsafe behavior.
- Compositional scenarios can reveal dominance, masking, and order effects that a single hazard does not.

## Avoid claiming

- Do not say replay proves causality.
- Do not say YAML attribution labels are per-run ground truth.
- Do not say raw trace LLM judging is the main attribution method.
- Do not say compositional playground replaces the main leaderboard.
- Do not say clean controls never fail.

## Preferred phrasing

- "observed failure path"
- "expected-vs-observed alignment"
- "replay-supported localization"
- "trajectory-safety pilot"
- "supplementary compositional stress suite"

