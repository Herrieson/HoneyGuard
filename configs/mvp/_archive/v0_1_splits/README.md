# Legacy v0.1 MVP Splits

Archived on 2026-04-30 while cleaning up `configs/mvp`.

Contents:

- `bootstrap/`: original bootstrap scenarios.
- `dev/`: v0.1 development split.
- `formal/`: v0.1 frozen test split.
- `pilot_b/`: old internal-authority pilot.

Compatibility:

- `scripts/assemble_mvp_benchmark.py --split dev` reads `dev/`.
- `scripts/assemble_mvp_benchmark.py --split test` reads `formal/`.
- `scripts/assemble_mvp_benchmark.py --split full` reads `dev/ + formal/`.
- `scripts/assemble_mvp_benchmark.py --split pilot_b` reads `pilot_b/`.

Current experiments should use `configs/mvp/v0_2/` and `--split v0_2_test`.
