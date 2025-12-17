from __future__ import annotations

from typing import Callable, Dict, Optional, List
import importlib

from langgraph.graph import END, StateGraph

from orchestration.state import AgentState
from orchestration.coordinator import AgentCoordinator
from langchain.tools import BaseTool


class EnvironmentRunner:
    """LangGraph-based runtime skeleton with pre-execution hook."""

    def __init__(
        self,
        coordinator: AgentCoordinator,
        pre_execution_hook: Optional[Callable[[AgentState], None]] = None,
        tools_by_name: Optional[Dict[str, BaseTool]] = None,
        max_steps: int = 3,
        stop_on_done: bool = True,
        graph_template: Optional[str] = None,
        stop_signals: Optional[List[str]] = None,
        max_elapsed_sec: Optional[float] = None,
    ) -> None:
        self.coordinator = coordinator
        self.pre_execution_hook = pre_execution_hook
        self.tools_by_name = tools_by_name or {}
        self.max_steps = max_steps
        self.stop_on_done = stop_on_done
        self.graph_template = graph_template
        self.stop_signals = [s.lower() for s in (stop_signals or ["done"])]
        self.max_elapsed_sec = max_elapsed_sec
        self.shared_context: Dict[str, object] = {}
        self.app = self._build_graph()

    def _build_graph(self):
        if self.graph_template:
            template_app = self._load_graph_template()
            if template_app is not None:
                return template_app
        workflow = StateGraph(AgentState)
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", self._tools_node)
        workflow.set_entry_point("agent")
        workflow.add_conditional_edges(
            "agent",
            self._route_from_agent,
            {"tools": "tools", "end": END},
        )
        workflow.add_conditional_edges(
            "tools",
            self._route_from_tools,
            {"agent": "agent", "end": END},
        )
        return workflow.compile()

    def _load_graph_template(self):
        try:
            module_path, func_name = self.graph_template.split(":")
        except Exception:
            return None
        try:
            module = importlib.import_module(module_path)
            func = getattr(module, func_name)
        except Exception:
            return None
        try:
            return func(
                coordinator=self.coordinator,
                tools_by_name=self.tools_by_name,
                pre_execution_hook=self.pre_execution_hook,
                max_steps=self.max_steps,
                stop_on_done=self.stop_on_done,
                stop_signals=self.stop_signals,
                max_elapsed_sec=self.max_elapsed_sec,
            )
        except Exception:
            return None

    def _route_from_agent(self, state: AgentState) -> str:
        env = state.get("env_status", {}) or {}
        if env.get("finished"):
            return "end"
        pending = state.get("pending_tool_calls") or []
        return "tools" if pending else "end"

    def _route_from_tools(self, state: AgentState) -> str:
        env = state.get("env_status", {}) or {}
        if env.get("finished"):
            return "end"
        return "agent"

    def _agent_node(self, state: AgentState) -> AgentState:
        env = state.get("env_status", {}) or {}
        step = int(env.get("step", 0)) + 1
        env["step"] = step
        state["env_status"] = env

        response, tool_calls, context_updates = self.coordinator.run(
            state.get("input", ""),
            tool_results=state.get("tool_results"),
            shared_context=state.get("shared_context") or self.shared_context,
        )
        state["last_response"] = response
        state["pending_tool_calls"] = [call.__dict__ for call in tool_calls]  # serialize ToolCall
        if context_updates:
            self._merge_shared_context(state, context_updates)

        if self.stop_on_done and response and self._has_stop_signal(response):
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
        pending = state.get("pending_tool_calls") or []
        results = state.get("tool_results") or []
        elapsed_total = env.get("tool_elapsed_total", 0.0) or 0.0

        for call in pending:
            name = call.get("name")
            args = call.get("args") or {}
            agent = call.get("agent")
            precomputed_output = call.get("output")
            precomputed_error = call.get("error")
            if precomputed_output is not None or precomputed_error is not None:
                results.append(
                    {
                        "name": name,
                        "args": args,
                        "output": precomputed_output,
                        "error": precomputed_error,
                        "agent": agent,
                        "elapsed_sec": None,
                        "status": "precomputed",
                    }
                )
                continue

            tool = self.tools_by_name.get(name)
            if not tool:
                results.append(
                    {
                        "name": name,
                        "args": args,
                        "output": None,
                        "error": f"Tool '{name}' not registered",
                        "agent": agent,
                        "elapsed_sec": None,
                        "status": "error",
                    }
                )
                continue
            import time as _time

            start = _time.monotonic()
            try:
                output = str(tool.invoke(args))
                error = None
                status = "ok"
            except Exception as exc:  # pragma: no cover - runtime errors
                output = None
                error = str(exc)
                status = "error"
            elapsed = _time.monotonic() - start
            elapsed_total += elapsed
            results.append(
                {
                    "name": name,
                    "args": args,
                    "output": output,
                    "error": error,
                    "agent": agent,
                    "elapsed_sec": elapsed,
                    "status": status,
                }
            )

        state["tool_results"] = results
        state["last_tool_calls"] = results
        state["pending_tool_calls"] = []
        env["tool_elapsed_total"] = elapsed_total
        if self.max_elapsed_sec and elapsed_total >= self.max_elapsed_sec:
            env["finished"] = True
        state["env_status"] = env
        return state

    def _has_stop_signal(self, text: str) -> bool:
        lowered = text.lower() if text else ""
        return any(sig in lowered for sig in self.stop_signals)

    def run(self, state: AgentState) -> AgentState:
        return self.app.invoke(state)

    def _merge_shared_context(self, state: AgentState, updates: Dict[str, object]) -> None:
        shared_ctx = {}
        shared_ctx.update(self.shared_context or {})
        shared_ctx.update(state.get("shared_context") or {})
        shared_ctx.update(updates or {})
        state["shared_context"] = shared_ctx
        self.shared_context = shared_ctx
