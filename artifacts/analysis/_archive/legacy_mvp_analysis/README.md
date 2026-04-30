# Legacy MVP Analysis Archive

Archived on 2026-04-30 after the MVP experiment outputs were moved to:

- `artifacts/experiments/mvp/_archive/legacy_exp6/`

This directory preserves old generated analysis outputs:

- `mvp/`

These files are kept for audit/reproducibility only. New v0.2 analysis should be regenerated into:

- `artifacts/analysis/mvp/`

Recommended regeneration command:

```bash
uv run python scripts/analysis/analyze_mvp_results.py \
  --root artifacts/experiments/mvp \
  --splits v0_2_test \
  --output artifacts/analysis/mvp
```
