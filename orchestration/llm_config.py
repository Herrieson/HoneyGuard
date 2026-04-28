from __future__ import annotations

import json
import os
from typing import Any, Dict


def _pick_from_env(config: Dict[str, Any], key: str, default: str | None = None) -> str | None:
    env_key = config.get(f"{key}_env")
    if isinstance(env_key, str) and env_key:
        return os.getenv(env_key, default)
    return config.get(key, default)


def _coerce_dict(value: Any, label: str) -> Dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} must be a JSON object") from exc
        if isinstance(parsed, dict):
            return parsed
    raise ValueError(f"{label} must be a JSON object")


def _pick_dict_from_env(config: Dict[str, Any], key: str) -> Dict[str, Any]:
    env_key = config.get(f"{key}_env")
    if isinstance(env_key, str) and env_key:
        env_value = os.getenv(env_key)
        if env_value is not None:
            return _coerce_dict(env_value, env_key)
    return _coerce_dict(config.get(key), key)


def _global_extra_body() -> Dict[str, Any]:
    for env_key in ("OPENAI_EXTRA_BODY", "HSE_LLM_EXTRA_BODY"):
        env_value = os.getenv(env_key)
        if env_value:
            return _coerce_dict(env_value, env_key)
    return {}


def _pick_compat_profile(config: Dict[str, Any]) -> str:
    explicit = _pick_from_env(config, "compat_profile", config.get("compat_profile"))
    if explicit:
        return explicit
    return os.getenv("HSE_LLM_COMPAT_PROFILE") or os.getenv("OPENAI_COMPAT_PROFILE") or "auto"


def resolve_llm_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve llm_config, allowing *_env to point to environment variable names."""
    fallback_model = os.getenv("HSE_LLM_MODEL") or "gpt-3.5-turbo-0125"
    extra_body = _pick_dict_from_env(config, "extra_body")
    extra_body.update(_global_extra_body())
    resolved = {
        "provider": config.get("provider", "openai"),
        "model": _pick_from_env(config, "model", config.get("model") or fallback_model),
        "api_key": _pick_from_env(config, "api_key", config.get("api_key")),
        "base_url": _pick_from_env(config, "base_url", config.get("base_url")),
        "api_version": _pick_from_env(config, "api_version", config.get("api_version")),
        "deployment_name": _pick_from_env(config, "deployment_name", config.get("deployment_name")),
        "organization": _pick_from_env(config, "organization", config.get("organization")),
        "extra_body": extra_body,
        "compat_profile": _pick_compat_profile(config),
    }
    return resolved
