from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentExecutionError(Exception):
    message: str
    error_type: str = "agent_execution_error"
    retryable: bool = False
    status_code: int = 500
    provider_status_code: Optional[int] = None
    attempts: int = 1
    retry_events: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "error_type": self.error_type,
            "retryable": self.retryable,
            "provider_status_code": self.provider_status_code,
            "attempts": self.attempts,
            "retry_events": list(self.retry_events or []),
        }


class AgentBlockedError(AgentExecutionError):
    def __init__(
        self,
        message: str,
        *,
        provider_status_code: Optional[int] = None,
        attempts: int = 1,
        retry_events: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(
            message=message,
            error_type="api_blocked",
            retryable=False,
            status_code=400,
            provider_status_code=provider_status_code,
            attempts=attempts,
            retry_events=list(retry_events or []),
        )


class AgentTransientError(AgentExecutionError):
    def __init__(
        self,
        message: str,
        *,
        error_type: str,
        status_code: int,
        provider_status_code: Optional[int] = None,
        attempts: int = 1,
        retry_events: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(
            message=message,
            error_type=error_type,
            retryable=True,
            status_code=status_code,
            provider_status_code=provider_status_code,
            attempts=attempts,
            retry_events=list(retry_events or []),
        )
