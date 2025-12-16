from __future__ import annotations

import yaml
from pathlib import Path
from typing import Dict, Any


CONFIG_PATH = Path(__file__).resolve().parent / "tools.yaml"


def load_tool_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        if not isinstance(data, dict):
            return {}
        return data
    return {}
