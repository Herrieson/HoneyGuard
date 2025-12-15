from __future__ import annotations

from typing import Callable, Dict, Optional

from langchain.tools import BaseTool
from langgraph.graph import END, StateGraph

from orchestration.state import AgentState


class EnvironmentRunner:
    """LangGraph-based runtime skeleton with pre-execution hook."""

    def __init__(
        self,
        tools: list[BaseTool],
        pre_execution_hook: Optional[Callable[[AgentState], None]] = None,
    ) -> None:
        self.tools = tools
        self.pre_execution_hook = pre_execution_hook
        self.app = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", self._tools_node)
        workflow.set_entry_point("agent")
        workflow.add_conditional_edges(
            "agent",
            self._route_from_agent,
            {"tools": "tools", "end": END},
        )
        workflow.add_edge("tools", "agent")
        return workflow.compile()

    def _route_from_agent(self, state: AgentState) -> str:
        env = state.get("env_status", {}) or {}
        if env.get("finished"):
            return "end"
        return "tools"

    def _agent_node(self, state: AgentState) -> AgentState:
        # Placeholder: real agent logic (LLM/tool selection) to be wired here.
        env = state.get("env_status", {}) or {}
        env.setdefault("cycle", 0)
        env["cycle"] = int(env["cycle"]) + 1
        state["env_status"] = env
        return state

    def _tools_node(self, state: AgentState) -> AgentState:
        if self.pre_execution_hook:
            self.pre_execution_hook(state)
        # Placeholder: tool dispatch should happen here once agent produces tool calls.
        env = state.get("env_status", {}) or {}
        env["finished"] = True
        state["env_status"] = env
        return state

    def run(self, state: AgentState) -> AgentState:
        return self.app.invoke(state)
