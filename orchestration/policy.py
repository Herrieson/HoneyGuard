from __future__ import annotations

import threading
from typing import Dict, Optional

from fastapi import HTTPException

from config.tool_config import load_tool_config


_TOOL_CALLS: Dict[str, int] = {}
_LOCK = threading.Lock()


def reset_session(session_id: str) -> None:
    with _LOCK:
        _TOOL_CALLS[session_id] = 0


def cleanup_session(session_id: str) -> None:
    with _LOCK:
        _TOOL_CALLS.pop(session_id, None)


def enforce_tool_quota(session_id: str) -> None:
    cfg = load_tool_config()
    max_calls = int(cfg.get("max_tool_calls_per_session") or 0)
    if max_calls <= 0:
        return
    with _LOCK:
        count = _TOOL_CALLS.get(session_id, 0)
        if count >= max_calls:
            raise HTTPException(status_code=429, detail="Tool call quota exceeded for session")
        _TOOL_CALLS[session_id] = count + 1


def is_write_allowed(tool_name: str) -> bool:
    cfg = load_tool_config()
    allowed = cfg.get("write_allowed_tools") or []
    return tool_name in allowed
