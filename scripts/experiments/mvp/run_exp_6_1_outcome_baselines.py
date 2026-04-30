#!/usr/bin/env python3
"""Legacy compatibility wrapper for run_mvp_outcome_benchmark.py."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.experiments.mvp.run_mvp_outcome_benchmark import main


if __name__ == "__main__":
    raise SystemExit(main())
