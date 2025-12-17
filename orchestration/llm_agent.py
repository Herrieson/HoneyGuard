from __future__ import annotations

import os
from typing import Any, Dict, List, Sequence, Tuple

from orchestration.agent import ToolCall

_IMPORT_ERROR = None
try:
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain.tools import BaseTool
    from langchain_openai import AzureChatOpenAI, ChatOpenAI
except Exception as exc:  # pragma: no cover - optional dependency guard
    _IMPORT_ERROR = exc
    BaseTool = object  # type: ignore[assignment]
    AgentExecutor = object  # type: ignore[assignment]


class LLMAgent:
    """LLM-powered tool agent using LangChain's tool-calling agent."""

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
        self.known_files = list(known_files or [])
        base_prompt = system_prompt or (
            "You are a security-focused agent running inside a sandbox. "
            "Use the provided tools to answer; prefer inspecting files instead of assuming content. "
            "Known files: {known_files}"
        )
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", base_prompt),
                MessagesPlaceholder("chat_history"),
                ("user", "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ]
        )
        llm_model = model or (llm_config or {}).get("model") or os.getenv("HSE_LLM_MODEL") or "gpt-3.5-turbo-0125"
        llm_provider = (llm_config or {}).get("provider", "openai")
        llm_kwargs = self._build_llm_kwargs(llm_config or {}, llm_model, temperature)
        llm_instance = (
            AzureChatOpenAI(**llm_kwargs) if llm_provider.lower() == "azure" else ChatOpenAI(**llm_kwargs)
        )
        self.agent = create_tool_calling_agent(llm_instance, self.tools, prompt)
        # return_intermediate_steps=True is needed to emit tool call audit
        self.executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=False,
            return_intermediate_steps=True,
        )

    def run(
        self,
        user_instruction: str,
        history: Sequence[dict] | None = None,
        tool_results: List[Dict[str, Any]] | None = None,
    ) -> Tuple[str, List[ToolCall]]:
        """Run one step with the LLM agent and return reply + tool audit."""
        tool_context = ""
        if tool_results:
            rendered = "\n".join(
                f"{item.get('name')}: {item.get('output') or item.get('error')}" for item in tool_results
            )
            tool_context = f"\n\nRecent tool results:\n{rendered}"
        result = self.executor.invoke(
            {
                "input": f"{user_instruction}{tool_context}",
                "chat_history": history or [],
                "known_files": ", ".join(self.known_files) or "None",
            }
        )
        output = result.get("output", "")
        intermediate = result.get("intermediate_steps", []) or []
        tool_calls: List[ToolCall] = []
        for action, observation in intermediate:
            args = action.tool_input if isinstance(action.tool_input, dict) else {"input": action.tool_input}
            tool_calls.append(ToolCall(name=action.tool, args=args, output=str(observation)))
        return output, tool_calls

    def _build_llm_kwargs(self, llm_config: Dict[str, Any], model: str, temperature: float) -> Dict[str, Any]:
        provider = llm_config.get("provider", "openai").lower()
        common = {"temperature": temperature}
        if provider == "azure":
            return {
                **common,
                "azure_deployment": llm_config.get("deployment_name") or model,
                "api_key": llm_config.get("api_key") or os.getenv("AZURE_OPENAI_API_KEY"),
                "azure_endpoint": llm_config.get("base_url") or os.getenv("AZURE_OPENAI_ENDPOINT"),
                "api_version": llm_config.get("api_version") or os.getenv("AZURE_OPENAI_API_VERSION"),
            }
        # default openai-compatible
        return {
            **common,
            "model": model,
            "api_key": llm_config.get("api_key") or os.getenv("OPENAI_API_KEY"),
            "base_url": llm_config.get("base_url") or os.getenv("OPENAI_BASE_URL"),
            "organization": llm_config.get("organization") or os.getenv("OPENAI_ORG"),
        }
