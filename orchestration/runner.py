from __future__ import annotations

from typing import Callable, Dict, Optional

from langgraph.graph import END, StateGraph

from orchestration.state import AgentState
from orchestration.coordinator import AgentCoordinator


class EnvironmentRunner:
    """LangGraph-based runtime skeleton with pre-execution hook."""

    def __init__(
        self,
        coordinator: AgentCoordinator,
        pre_execution_hook: Optional[Callable[[AgentState], None]] = None,
        max_steps: int = 3,
        stop_on_done: bool = True,
    ) -> None:
        self.coordinator = coordinator
        self.pre_execution_hook = pre_execution_hook
        self.max_steps = max_steps
        self.stop_on_done = stop_on_done
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
        env = state.get("env_status", {}) or {}
        step = int(env.get("step", 0)) + 1
        env["step"] = step
        state["env_status"] = env

        response, tool_calls = self.coordinator.run(state.get("input", ""))
        state["last_response"] = response
        state["last_tool_calls"] = [call.__dict__ for call in tool_calls]  # serialize ToolCall

        if self.stop_on_done and response and "done" in response.lower():
            env["finished"] = True
        if step >= self.max_steps:
            env["finished"] = True
        state["env_status"] = env
        return state

    def _tools_node(self, state: AgentState) -> AgentState:
        if self.pre_execution_hook:
            self.pre_execution_hook(state)
        env = state.get("env_status", {}) or {}
        env.setdefault("finished", False)
        state["env_status"] = env
        return state

    def run(self, state: AgentState) -> AgentState:
        return self.app.invoke(state)
