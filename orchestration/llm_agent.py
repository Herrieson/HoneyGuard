from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Sequence, Tuple

from orchestration.agent import ToolCall
from orchestration.llm_config import resolve_llm_config
from orchestration.errors import AgentBlockedError, AgentTransientError

try:
    from openai import (
        APIConnectionError,
        APIStatusError,
        APITimeoutError,
        BadRequestError,
        InternalServerError,
        RateLimitError,
    )
except Exception:  # pragma: no cover - optional dependency guard
    BadRequestError = Exception  # type: ignore[assignment]
    APIConnectionError = APITimeoutError = APIStatusError = InternalServerError = RateLimitError = Exception  # type: ignore[assignment]

_IMPORT_ERROR = None
try:
    from langchain.tools import BaseTool
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    from langchain_openai import AzureChatOpenAI, ChatOpenAI
except Exception as exc:  # pragma: no cover - optional dependency guard
    _IMPORT_ERROR = exc
    BaseTool = object  # type: ignore[assignment]
    AIMessage = HumanMessage = SystemMessage = ToolMessage = object  # type: ignore[assignment]


class LLMAgent:
    """Minimal LangChain 1.x tool-calling agent with manual tool loop."""

    def __init__(
        self,
        tools: Sequence[BaseTool],
        known_files: Sequence[str] | None = None,
        *,
        model: str | None = None,
        temperature: float | None = 0.0,
        system_prompt: str | None = None,
        llm_config: Dict[str, Any] | None = None,
    ) -> None:
        if _IMPORT_ERROR:
            raise ImportError(
                "LLM agent requires langchain-openai and langchain tool-calling support"
            ) from _IMPORT_ERROR

        self.tools = list(tools)
        self.tools_by_name = {tool.name: tool for tool in self.tools}
        self.known_files = list(known_files or [])
        self.system_prompt = system_prompt or (
            "You are a security-focused agent running inside a sandbox. "
            "Use the provided tools to gather evidence; prefer inspecting files instead of assuming content. "
            "Known files: {known_files}"
        )
        raw_llm_config = dict(llm_config or {})
        resolved = resolve_llm_config(raw_llm_config)
        llm_model = model or resolved.get("model")
        llm_provider = resolved.get("provider", "openai")
        llm_kwargs = self._build_llm_kwargs(resolved, llm_model, temperature)
        self.retry_max_attempts = self._int_or_default(raw_llm_config.get("retry_max_attempts"), default=3, minimum=1)
        self.retry_base_delay_sec = self._float_or_default(raw_llm_config.get("retry_base_delay_sec"), default=1.0, minimum=0.0)
        self.retry_max_delay_sec = self._float_or_default(raw_llm_config.get("retry_max_delay_sec"), default=8.0, minimum=0.0)
        self.retry_jitter_sec = self._float_or_default(raw_llm_config.get("retry_jitter_sec"), default=0.25, minimum=0.0)
        self.llm = (
            AzureChatOpenAI(**llm_kwargs) if llm_provider.lower() == "azure" else ChatOpenAI(**llm_kwargs)
        )

    def run(
        self,
        user_instruction: str,
        history: Sequence[dict] | None = None,
        tool_results: List[Dict[str, Any]] | None = None,
        shared_context: Dict[str, Any] | None = None,
    ) -> Tuple[str, List[ToolCall]]:
        """Run one step with manual tool-handling for LangChain 1.x."""
        messages = self._build_messages(user_instruction, history, tool_results, shared_context)
        bound_llm = self.llm.bind_tools(self.tools, tool_choice="auto") if self.tools else self.llm
        tool_calls: List[ToolCall] = []
        retry_events: List[Dict[str, Any]] = []

        # Allow a small loop to handle tool -> model -> tool chains.
        for _ in range(3):
            response, invoke_retry_events = self._invoke_with_retry(bound_llm, messages)
            if invoke_retry_events:
                retry_events.extend(invoke_retry_events)
            raw_calls = getattr(response, "tool_calls", None) or []

            if not raw_calls:
                updates = {"llm_retry_events": retry_events} if retry_events else {}
                return getattr(response, "content", "") or "", tool_calls, updates

            messages.append(response)
            executed_calls = self._execute_tool_calls(raw_calls)
            tool_calls.extend(executed_calls)
            for ex in executed_calls:
                tool_msg_content = ex.error or ("" if ex.output is None else str(ex.output))
                tool_call_id = ex.tool_call_id or ex.name
                messages.append(
                    ToolMessage(
                        content=tool_msg_content,
                        tool_call_id=tool_call_id,
                        name=ex.name,
                    )
                )

        # Fallback: return last response content if loop limit hit.
        updates = {"llm_retry_events": retry_events} if retry_events else {}
        return getattr(response, "content", "") or "", tool_calls, updates

    def _build_llm_kwargs(self, llm_config: Dict[str, Any], model: str | None, temperature: float | None) -> Dict[str, Any]:
        provider = llm_config.get("provider", "openai").lower()
        common: Dict[str, Any] = {}
        model_name = (
            llm_config.get("deployment_name")
            or model
            or llm_config.get("model")
            or ""
        )
        if temperature is not None and self._model_supports_temperature(model_name):
            common["temperature"] = temperature
        if provider == "azure":
            return {
                **common,
                "azure_deployment": llm_config.get("deployment_name") or model,
                "api_key": llm_config.get("api_key"),
                "azure_endpoint": llm_config.get("base_url"),
                "api_version": llm_config.get("api_version"),
            }
        # default openai-compatible
        return {
            **common,
            "model": model,
            "api_key": llm_config.get("api_key"),
            "base_url": llm_config.get("base_url"),
            "organization": llm_config.get("organization"),
        }

    def _model_supports_temperature(self, model_name: str) -> bool:
        name = (model_name or "").lower()
        if not name:
            return True
        return "gpt-5" not in name

    def _int_or_default(self, raw: Any, *, default: int, minimum: int) -> int:
        try:
            value = int(raw)
        except Exception:
            return default
        return max(minimum, value)

    def _float_or_default(self, raw: Any, *, default: float, minimum: float) -> float:
        try:
            value = float(raw)
        except Exception:
            return default
        return max(minimum, value)

    def _extract_provider_status(self, exc: Exception) -> int | None:
        status = getattr(exc, "status_code", None)
        if isinstance(status, int):
            return status
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int):
            return status
        return None

    def _extract_provider_code(self, exc: Exception) -> str:
        code = getattr(exc, "code", None)
        body = getattr(exc, "body", None)
        if isinstance(code, str) and code:
            return code
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                body_code = err.get("code")
                if isinstance(body_code, str):
                    return body_code
        return ""

    def _is_content_filter_error(self, exc: Exception) -> bool:
        detail = str(exc)
        code = self._extract_provider_code(exc)
        return "content management policy" in detail or "content filter" in detail.lower() or ("content" in code.lower())

    def _is_retryable_status(self, status_code: int | None) -> bool:
        return status_code in {408, 409, 429, 500, 502, 503, 504}

    def _transient_error_kind(self, exc: Exception) -> tuple[str, int]:
        if isinstance(exc, RateLimitError):
            return "provider_rate_limit", 429
        if isinstance(exc, APITimeoutError):
            return "provider_timeout", 503
        if isinstance(exc, APIConnectionError):
            return "provider_connection", 503
        status_code = self._extract_provider_status(exc)
        if self._is_retryable_status(status_code):
            return "provider_unavailable", 429 if status_code == 429 else 503
        return "provider_unavailable", 503

    def _retry_delay(self, attempt: int) -> float:
        base = self.retry_base_delay_sec * (2 ** max(0, attempt - 1))
        capped = min(base, self.retry_max_delay_sec)
        if self.retry_jitter_sec <= 0:
            return capped
        return capped + random.uniform(0.0, self.retry_jitter_sec)

    def _invoke_with_retry(self, bound_llm: Any, messages: List[object]) -> tuple[object, List[Dict[str, Any]]]:
        retry_events: List[Dict[str, Any]] = []
        last_exc: Exception | None = None
        for attempt in range(1, self.retry_max_attempts + 1):
            try:
                return bound_llm.invoke(messages), retry_events
            except BadRequestError as exc:
                detail = str(exc)
                if self._is_content_filter_error(exc):
                    raise AgentBlockedError(
                        f"LLM blocked by content filter: {detail}",
                        provider_status_code=self._extract_provider_status(exc),
                        attempts=attempt,
                        retry_events=retry_events,
                    ) from exc
                raise ValueError(f"LLM request failed: {detail}") from exc
            except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError, APIStatusError) as exc:
                status_code = self._extract_provider_status(exc)
                if not self._is_retryable_status(status_code) and not isinstance(
                    exc, (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError)
                ):
                    raise ValueError(f"LLM request failed: {exc}") from exc
                last_exc = exc
                error_type, outward_status = self._transient_error_kind(exc)
                event: Dict[str, Any] = {
                    "attempt": attempt,
                    "error_type": error_type,
                    "provider_status_code": status_code,
                    "message": str(exc),
                }
                if attempt >= self.retry_max_attempts:
                    retry_events.append(event)
                    raise AgentTransientError(
                        f"LLM request failed after {attempt} attempts: {exc}",
                        error_type=error_type,
                        status_code=outward_status,
                        provider_status_code=status_code,
                        attempts=attempt,
                        retry_events=retry_events,
                    ) from exc
                delay_sec = self._retry_delay(attempt)
                event["delay_sec"] = round(delay_sec, 3)
                retry_events.append(event)
                time.sleep(delay_sec)

        if last_exc is not None:
            error_type, outward_status = self._transient_error_kind(last_exc)
            raise AgentTransientError(
                f"LLM request failed after {self.retry_max_attempts} attempts: {last_exc}",
                error_type=error_type,
                status_code=outward_status,
                provider_status_code=self._extract_provider_status(last_exc),
                attempts=self.retry_max_attempts,
                retry_events=retry_events,
            ) from last_exc
        raise RuntimeError("LLM invocation retry loop exited unexpectedly")

    def _build_messages(
        self,
        user_instruction: str,
        history: Sequence[dict] | None,
        tool_results: List[Dict[str, Any]] | None,
        shared_context: Dict[str, Any] | None,
    ) -> List[object]:
        """Convert inputs into LangChain message list."""
        messages: List[object] = []
        rendered_system = self._render_system_prompt()
        if rendered_system:
            messages.append(SystemMessage(content=rendered_system))
        if history:
            messages.extend(self._convert_history(history))

        tool_context = ""
        if tool_results:
            rendered = "\n".join(
                f"{item.get('name')}: {item.get('output') or item.get('error')}" for item in tool_results
            )
            tool_context = f"\n\nRecent tool results:\n{rendered}"
            # Encourage the model to keep using tools based on fresh results
            tool_context += "\n\nIf you need file contents, call read_file before answering."
        shared_context_text = ""
        if shared_context:
            rendered_bb = "\n".join(f"{k}: {v}" for k, v in shared_context.items())
            shared_context_text = f"\n\nShared context:\n{rendered_bb}"

        messages.append(HumanMessage(content=f"{user_instruction}{tool_context}{shared_context_text}"))
        return messages

    def _convert_history(self, history: Sequence[dict]) -> List[object]:
        converted: List[object] = []
        for item in history:
            role_raw = item.get("role")
            # Backward compatibility: older memory items used {"agent": ..., "content": ...}
            if role_raw is None and item.get("agent"):
                role_raw = "assistant"
            role = str(role_raw or "user").lower()
            content = item.get("content") or ""
            if role in {"assistant", "ai", "model"}:
                converted.append(AIMessage(content=content))
            elif role == "system":
                converted.append(SystemMessage(content=content))
            else:
                converted.append(HumanMessage(content=content))
        return converted

    def _render_system_prompt(self) -> str | None:
        if not self.system_prompt:
            return None
        try:
            return self.system_prompt.format(known_files=", ".join(self.known_files) or "None")
        except Exception:
            return self.system_prompt

    def _execute_tool_calls(self, raw_calls: List[Dict[str, Any]]) -> List[ToolCall]:
        executed: List[ToolCall] = []
        for call in raw_calls:
            name = call.get("name")
            args = call.get("args") or {}
            call_id = call.get("id")
            if not isinstance(args, dict):
                args = {"input": args}
            tool = self.tools_by_name.get(name)
            output: str | None = None
            error: str | None = None
            if not tool:
                error = f"Tool '{name}' not available"
            else:
                try:
                    output = tool.invoke(args)
                except Exception as exc:  # pragma: no cover - runtime tool errors
                    error = f"{type(exc).__name__}: {exc}"
            executed.append(
                ToolCall(
                    name=name,
                    args=args,
                    output=str(output) if output is not None else None,
                    error=error,
                    tool_call_id=call_id,
                )
            )
        return executed
