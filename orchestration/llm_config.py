from __future__ import annotations

import os
from typing import Any, Dict


def _pick_from_env(config: Dict[str, Any], key: str, default: str | None = None) -> str | None:
    env_key = config.get(f"{key}_env")
    if isinstance(env_key, str) and env_key:
        return os.getenv(env_key, default)
    return config.get(key, default)


def resolve_llm_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve llm_config, allowing *_env to point to environment variable names."""
    fallback_model = os.getenv("HSE_LLM_MODEL") or "gpt-3.5-turbo-0125"
    resolved = {
        "provider": config.get("provider", "openai"),
        "model": _pick_from_env(config, "model", config.get("model") or fallback_model),
        "api_key": _pick_from_env(config, "api_key", config.get("api_key")),
        "base_url": _pick_from_env(config, "base_url", config.get("base_url")),
        "api_version": _pick_from_env(config, "api_version", config.get("api_version")),
        "deployment_name": _pick_from_env(config, "deployment_name", config.get("deployment_name")),
        "organization": _pick_from_env(config, "organization", config.get("organization")),
    }
    return resolved
