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


def get_default_limits() -> Dict[str, Any]:
    cfg = load_tool_config()
    return {
        "timeout_sec": cfg.get("default_timeout_sec"),
        "cpu_limit": cfg.get("default_cpu_limit"),
        "mem_limit": cfg.get("default_mem_limit"),
    }
