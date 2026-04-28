from __future__ import annotations

from typing import Any, Dict


AUTO_PROFILE = "auto"
NO_COMPAT_PROFILE = "none"
OPENAI_COMPATIBLE_PROFILE = "openai-compatible"
DEEPSEEK_V4_PROFILE = "deepseek-v4"
GEMINI_3_PROFILE = "gemini-3"
GEMINI_DUMMY_THOUGHT_SIGNATURE = "skip_thought_signature_validator"


def resolve_compat_profile(llm_config: Dict[str, Any], model_name: str | None) -> str:
    requested = str(llm_config.get("compat_profile") or AUTO_PROFILE).strip().lower()
    if requested in {"", AUTO_PROFILE}:
        return _auto_profile(model_name)
    if requested in {"off", "disable", "disabled", "false", NO_COMPAT_PROFILE}:
        return NO_COMPAT_PROFILE
    if requested in {"deepseek", DEEPSEEK_V4_PROFILE}:
        return DEEPSEEK_V4_PROFILE
    if requested in {"gemini", "google-gemini", GEMINI_3_PROFILE}:
        return GEMINI_3_PROFILE
    if requested in {"openai", OPENAI_COMPATIBLE_PROFILE}:
        return OPENAI_COMPATIBLE_PROFILE
    return requested


def _auto_profile(model_name: str | None) -> str:
    name = (model_name or "").lower()
    if "deepseek-v4" in name:
        return DEEPSEEK_V4_PROFILE
    if "gemini-3" in name:
        return GEMINI_3_PROFILE
    return OPENAI_COMPATIBLE_PROFILE


def build_extra_body(llm_config: Dict[str, Any], compat_profile: str) -> Dict[str, Any]:
    extra_body = dict(llm_config.get("extra_body") or {})
    if compat_profile == DEEPSEEK_V4_PROFILE and "thinking" not in extra_body:
        extra_body["thinking"] = {"type": "disabled"}
    return extra_body


def prepare_ai_message_for_tool_response(response: Any, compat_profile: str) -> None:
    if compat_profile != GEMINI_3_PROFILE:
        return
    tool_calls = getattr(response, "tool_calls", None) or []
    add_gemini_thought_signatures(tool_calls)


def add_gemini_thought_signatures(tool_calls: list[Dict[str, Any]]) -> None:
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        extra_content = call.get("extra_content")
        if not isinstance(extra_content, dict):
            extra_content = {}
            call["extra_content"] = extra_content
        google_extra = extra_content.get("google")
        if not isinstance(google_extra, dict):
            google_extra = {}
            extra_content["google"] = google_extra
        google_extra.setdefault("thought_signature", GEMINI_DUMMY_THOUGHT_SIGNATURE)


def install_langchain_openai_extra_content_patch() -> None:
    try:
        from langchain_openai.chat_models import base as langchain_openai_base
    except Exception:
        return

    current = getattr(langchain_openai_base, "_lc_tool_call_to_openai_tool_call", None)
    if not callable(current) or getattr(current, "_honeyguard_preserves_extra_content", False):
        return

    def wrapped(tool_call: Any) -> Dict[str, Any]:
        payload = current(tool_call)
        extra_content = tool_call.get("extra_content") if isinstance(tool_call, dict) else None
        if isinstance(extra_content, dict):
            payload["extra_content"] = extra_content
        return payload

    wrapped._honeyguard_preserves_extra_content = True  # type: ignore[attr-defined]
    langchain_openai_base._lc_tool_call_to_openai_tool_call = wrapped
