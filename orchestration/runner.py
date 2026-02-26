from __future__ import annotations

from typing import Callable, Dict, Optional, List, Any
import importlib
import hashlib
import json

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
        max_tool_calls: Optional[int] = None,
        max_tool_repeats: Optional[int] = 2,
        stop_on_repeat_tool_calls: bool = True,
        stop_on_no_new_tool_results: bool = True,
        tool_finish_signals: Optional[List[str]] = None,
    ) -> None:
        self.coordinator = coordinator
        self.pre_execution_hook = pre_execution_hook
        self.tools_by_name = tools_by_name or {}
        self.max_steps = max_steps
        self.stop_on_done = stop_on_done
        self.graph_template = graph_template
        self.stop_signals = [s.lower() for s in (stop_signals or ["done"])]
        self.max_elapsed_sec = max_elapsed_sec
        self.max_tool_calls = max_tool_calls
        self.max_tool_repeats = max_tool_repeats
        self.stop_on_repeat_tool_calls = stop_on_repeat_tool_calls
        self.stop_on_no_new_tool_results = stop_on_no_new_tool_results
        self.tool_finish_signals = [s.lower() for s in (tool_finish_signals or ["done", "no-op", "noop"])]
        self.shared_context: Dict[str, object] = {}
        self.app = self._build_graph()

    def _build_graph(self):
        if self.graph_template:
            template_app = self._load_graph_template()
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
        except Exception as exc:
            raise ValueError(f"Invalid graph_template format: {self.graph_template}") from exc
        try:
            module = importlib.import_module(module_path)
            func = getattr(module, func_name)
        except Exception as exc:
            raise ValueError(f"Failed to import graph_template {self.graph_template}: {exc}") from exc
        try:
            app = func(
                coordinator=self.coordinator,
                tools_by_name=self.tools_by_name,
                pre_execution_hook=self.pre_execution_hook,
                max_steps=self.max_steps,
                stop_on_done=self.stop_on_done,
                stop_signals=self.stop_signals,
                max_elapsed_sec=self.max_elapsed_sec,
            )
        except Exception as exc:
            raise ValueError(f"Error constructing graph_template {self.graph_template}: {exc}") from exc
        if not hasattr(app, "invoke"):
            raise ValueError(f"graph_template {self.graph_template} did not return a LangGraph app with invoke().")
        return app

    def _route_from_agent(self, state: AgentState) -> str:
        env = state.get("env_status", {}) or {}
        pending = state.get("pending_tool_calls") or []
        if pending:
            return "tools"
        if env.get("finished"):
            return "end"
        return "end"

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
        pending_calls = [call.__dict__ for call in tool_calls]  # serialize ToolCall
        state["pending_tool_calls"] = pending_calls
        if context_updates:
            self._merge_shared_context(state, context_updates)

        if context_updates:
            if context_updates.get("final") is True or context_updates.get("done") is True:
                env["finished"] = True

        # Stop if the agent is repeating the exact same tool calls as last step.
        if self.stop_on_repeat_tool_calls and pending_calls:
            sig = self._tool_call_signature_list(pending_calls)
            if sig and sig == env.get("last_tool_call_sig"):
                env["finished"] = True
                state["pending_tool_calls"] = []
            else:
                env["last_tool_call_sig"] = sig

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
        tool_calls_total = int(env.get("tool_calls_total", 0) or 0)
        tool_call_counts: Dict[str, int] = env.get("tool_call_counts") or {}
        batch_results: List[Dict[str, object]] = []

        for call in pending:
            if self.max_tool_calls and tool_calls_total >= self.max_tool_calls:
                env["finished"] = True
                results.append(
                    {
                        "name": call.get("name"),
                        "args": call.get("args") or {},
                        "output": None,
                        "error": f"tool call budget exceeded (max_tool_calls={self.max_tool_calls})",
                        "agent": call.get("agent"),
                        "elapsed_sec": None,
                        "status": "skipped_budget",
                    }
                )
                continue

            sig = self._tool_call_signature(call)
            if self.max_tool_repeats is not None:
                seen = tool_call_counts.get(sig, 0)
                if seen >= self.max_tool_repeats:
                    env["finished"] = True
                    results.append(
                        {
                            "name": call.get("name"),
                            "args": call.get("args") or {},
                            "output": None,
                            "error": f"tool call repeat limit reached for {sig}",
                            "agent": call.get("agent"),
                            "elapsed_sec": None,
                            "status": "skipped_repeat_limit",
                        }
                    )
                    continue
                tool_call_counts[sig] = seen + 1

            name = call.get("name")
            args = call.get("args") or {}
            agent = call.get("agent")
            precomputed_output = call.get("output")
            precomputed_error = call.get("error")
            if precomputed_output is not None or precomputed_error is not None:
                record = (
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
                results.append(record)
                batch_results.append(record)
                tool_calls_total += 1
                if self._tool_signals_finish(precomputed_output, precomputed_error):
                    env["finished"] = True
                continue

            tool = self.tools_by_name.get(name)
            if not tool:
                record = (
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
                results.append(record)
                batch_results.append(record)
                tool_calls_total += 1
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
            record = (
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
            results.append(record)
            batch_results.append(record)
            tool_calls_total += 1
            if self._tool_signals_finish(output, error):
                env["finished"] = True

        state["tool_results"] = results
        state["last_tool_calls"] = results
        state["pending_tool_calls"] = []
        env["tool_calls_total"] = tool_calls_total
        env["tool_call_counts"] = tool_call_counts
        env["tool_elapsed_total"] = elapsed_total
        if self.max_elapsed_sec and elapsed_total >= self.max_elapsed_sec:
            env["finished"] = True
        if self.stop_on_no_new_tool_results and batch_results:
            batch_hash = self._tool_results_hash(batch_results)
            if batch_hash == env.get("last_tool_result_hash"):
                env["finished"] = True
            env["last_tool_result_hash"] = batch_hash
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

    def _tool_call_signature(self, call: Dict[str, Any]) -> str:
        name = call.get("name") or ""
        args = call.get("args") or {}
        if isinstance(args, dict):
            args = {k: v for k, v in args.items() if v is not None}
        try:
            args_text = json.dumps(args, sort_keys=True, separators=(",", ":"))
        except Exception:
            args_text = str(args)
        return f"{name}:{args_text}"

    def _tool_call_signature_list(self, calls: List[Dict[str, Any]]) -> List[str]:
        return [self._tool_call_signature(call) for call in calls]

    def _tool_results_hash(self, results: List[Dict[str, object]]) -> str:
        digest = hashlib.sha256()
        for item in results:
            chunk = json.dumps(item, sort_keys=True, default=str).encode("utf-8")
            digest.update(chunk)
        return digest.hexdigest()

    def _tool_signals_finish(self, output: Any, error: Any) -> bool:
        hay = f"{output or ''}\n{error or ''}".lower()
        return any(sig in hay for sig in self.tool_finish_signals)
