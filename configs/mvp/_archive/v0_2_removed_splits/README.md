# Removed v0.2 Working Splits

Archived on 2026-04-30 while simplifying the active v0.2 dataset layout.

Changes:

- `candidates_promoted_20260430/`: formerly `configs/mvp/v0_2/candidates/`; YAML files were promoted into `configs/mvp/v0_2/test/`.
- `b_smoke_20260430/`: formerly `configs/mvp/v0_2/b_smoke/`; this was a wrapper-only convenience split over B1/B2/B3 samples that already live in `v0_2/test`.

Current active v0.2 layout:

- `configs/mvp/v0_2/test/`: main test split.
- `configs/mvp/v0_2/dev/`: reserved development split.
- `configs/mvp/v0_2/docs/`: v0.2 notes.
