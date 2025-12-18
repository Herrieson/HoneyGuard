from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from orchestration.agent import ToolCall
from orchestration.llm_config import resolve_llm_config

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
        temperature: float = 0.0,
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
        resolved = resolve_llm_config(llm_config or {})
        llm_model = model or resolved.get("model")
        llm_provider = resolved.get("provider", "openai")
        llm_kwargs = self._build_llm_kwargs(resolved, llm_model, temperature)
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

        # Allow a small loop to handle tool -> model -> tool chains.
        for _ in range(3):
            response = bound_llm.invoke(messages)
            raw_calls = getattr(response, "tool_calls", None) or []

            if not raw_calls:
                return getattr(response, "content", "") or "", tool_calls, {}

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
        return getattr(response, "content", "") or "", tool_calls, {}

    def _build_llm_kwargs(self, llm_config: Dict[str, Any], model: str, temperature: float) -> Dict[str, Any]:
        provider = llm_config.get("provider", "openai").lower()
        common = {"temperature": temperature}
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
            role = (item.get("role") or "user").lower()
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
