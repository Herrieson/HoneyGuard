from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple, Dict

from orchestration.agent import ToolCall


@dataclass
class AgentWrapper:
    name: str
    mode: str
    impl: object
    memory_mode: str = "window"
    blackboard_read_keys: list[str] | None = None
    blackboard_write_keys: list[str] | None = None


class AgentCoordinator:
    """Multi-agent coordinator with simple patterns."""

    def __init__(
        self,
        agents: Sequence[AgentWrapper],
        pattern: str = "sequential",
        max_cycles: int = 1,
        stop_on_done: bool = True,
        memory_limit: int = 10,
        stop_signals: Sequence[str] | None = None,
    ) -> None:
        self.agents = list(agents)
        self.pattern = (pattern or "sequential").lower()
        self.max_cycles = max(1, int(max_cycles))
        self.stop_on_done = stop_on_done
        self.memory_limit = max(memory_limit, 1)
        self._memories: dict[str, list[dict]] = {}
        self.stop_signals = [s.lower() for s in (stop_signals or ["done"])]
        self._shared_context: dict[str, object] = {}

    def run(
        self, user_instruction: str, tool_results: List[dict] | None = None, shared_context: dict | None = None
    ) -> Tuple[str, List[ToolCall], Dict[str, object]]:
        self._shared_context = shared_context or {}
        transcript: List[dict] = []
        tool_calls: List[ToolCall] = []
        context_updates: dict[str, object] = {}
        stop = False

        if self.pattern == "round_robin":
            for _ in range(self.max_cycles):
                for agent in self.agents:
                    prompt = self._build_prompt(user_instruction, transcript, tool_results, agent)
                    response, calls, updates = self._run_agent(agent, prompt, tool_results)
                    if updates:
                        filtered = self._filter_writes(agent, updates)
                        context_updates.update(filtered)
                        self._shared_context.update(filtered)
                    self._record(agent.name, response)
                    transcript.append({"agent": agent.name, "content": response})
                    self._append_calls(tool_calls, calls, agent.name)
                    if self.stop_on_done and self._is_done(response):
                        stop = True
                        break
                if stop:
                    break
        elif self.pattern == "parallel":
            prompt = self._build_prompt(user_instruction, transcript, tool_results, None)
            for agent in self.agents:
                response, calls, updates = self._run_agent(agent, prompt, tool_results)
                if updates:
                    filtered = self._filter_writes(agent, updates)
                    context_updates.update(filtered)
                    self._shared_context.update(filtered)
                self._record(agent.name, response)
                transcript.append({"agent": agent.name, "content": response})
                self._append_calls(tool_calls, calls, agent.name)
        elif self.pattern == "planner_executor_verifier" and len(self.agents) >= 2:
            planner = self.agents[0]
            executor = self.agents[1]
            verifier = self.agents[2] if len(self.agents) > 2 else None

            # Planner step
            plan_prompt = self._build_prompt(user_instruction, transcript, tool_results, planner)
            plan_resp, plan_calls, plan_updates = self._run_agent(planner, plan_prompt, tool_results)
            if plan_updates:
                filtered = self._filter_writes(planner, plan_updates)
                context_updates.update(filtered)
                self._shared_context.update(filtered)
            self._record(planner.name, plan_resp)
            transcript.append({"agent": planner.name, "content": plan_resp})
            self._append_calls(tool_calls, plan_calls, planner.name)
            if self.stop_on_done and self._is_done(plan_resp):
                stop = True

            # Executor step(s)
            if not stop:
                exec_prompt = self._build_prompt(plan_resp, transcript, tool_results, executor)
                exec_resp, exec_calls, exec_updates = self._run_agent(executor, exec_prompt, tool_results)
                if exec_updates:
                    filtered = self._filter_writes(executor, exec_updates)
                    context_updates.update(filtered)
                    self._shared_context.update(filtered)
                self._record(executor.name, exec_resp)
                transcript.append({"agent": executor.name, "content": exec_resp})
                self._append_calls(tool_calls, exec_calls, executor.name)
                if self.stop_on_done and self._is_done(exec_resp):
                    stop = True

            # Verifier step (optional)
            if verifier and not stop:
                ver_prompt = self._build_prompt(exec_resp, transcript, tool_results, verifier)
                ver_resp, ver_calls, ver_updates = self._run_agent(verifier, ver_prompt, tool_results)
                if ver_updates:
                    filtered = self._filter_writes(verifier, ver_updates)
                    context_updates.update(filtered)
                    self._shared_context.update(filtered)
                self._record(verifier.name, ver_resp)
                transcript.append({"agent": verifier.name, "content": ver_resp})
                self._append_calls(tool_calls, ver_calls, verifier.name)
        else:  # sequential default
            for agent in self.agents:
                prompt = self._build_prompt(user_instruction, transcript, tool_results, agent)
                response, calls, updates = self._run_agent(agent, prompt, tool_results)
                if updates:
                    filtered = self._filter_writes(agent, updates)
                    context_updates.update(filtered)
                    self._shared_context.update(filtered)
                self._record(agent.name, response)
                transcript.append({"agent": agent.name, "content": response})
                self._append_calls(tool_calls, calls, agent.name)
                if self.stop_on_done and self._is_done(response):
                    break

        final_response = "\n".join(f"{m['agent']}: {m['content']}" for m in transcript) if transcript else ""
        return final_response, tool_calls, context_updates

    def _build_prompt(self, user_instruction: str, transcript: List[dict], tool_results: List[dict] | None, agent: AgentWrapper | None) -> str:
        base = user_instruction
        if transcript:
            history = "\n".join(f"{m['agent']}: {m['content']}" for m in transcript)
            base = f"{user_instruction}\n\nContext from previous agents:\n{history}"
        if tool_results:
            rendered = "\n".join(
                f"{item.get('name')}: {item.get('output') or item.get('error')}" for item in tool_results
            )
            base = f"{base}\n\nRecent tool results:\n{rendered}"
        if agent and hasattr(agent, "blackboard_read_keys"):
            readable = self._filter_reads(agent, self._shared_context or {})
            if readable:
                rendered_bb = "\n".join(f"{k}: {v}" for k, v in readable.items())
                base = f"{base}\n\nShared context:\n{rendered_bb}"
        return base

    def _run_agent(self, agent: AgentWrapper, prompt: str, tool_results: List[dict] | None):
        history = self._memory_for(agent.name) if agent.memory_mode != "none" else []
        readable = self._filter_reads(agent, self._shared_context or {})
        result = agent.impl.run(prompt, history=history, tool_results=tool_results, shared_context=readable)
        return self._validate_agent_result(agent.name, result)

    def _append_calls(self, tool_calls: List[ToolCall], calls: List[ToolCall], agent_name: str) -> None:
        for call in calls:
            call.agent = agent_name
            tool_calls.append(call)

    def _record(self, agent_name: str, content: str) -> None:
        history = self._memories.setdefault(agent_name, [])
        wrapper = next((a for a in self.agents if a.name == agent_name), None)
        memory_mode = wrapper.memory_mode if wrapper else "window"
        if memory_mode == "none":
            return
        history.append({"agent": agent_name, "content": content})
        if len(history) > self.memory_limit:
            del history[0 : len(history) - self.memory_limit]

    def _memory_for(self, agent_name: str) -> List[dict]:
        return list(self._memories.get(agent_name, []))

    def _is_done(self, text: str) -> bool:
        lowered = text.lower() if text else ""
        return any(sig in lowered for sig in self.stop_signals)

    def _filter_reads(self, agent: AgentWrapper, shared_context: dict) -> dict:
        keys = agent.blackboard_read_keys or ["*"]
        if "*" in keys:
            return dict(shared_context)
        return {k: v for k, v in shared_context.items() if k in keys}

    def _filter_writes(self, agent: AgentWrapper, updates: dict) -> dict:
        keys = agent.blackboard_write_keys or ["*"]
        if "*" in keys:
            return dict(updates)
        return {k: v for k, v in updates.items() if k in keys}

    def _validate_agent_result(self, agent_name: str, result) -> Tuple[str, List[ToolCall], Dict[str, object]]:
        if not isinstance(result, tuple):
            raise TypeError(
                f"Agent '{agent_name}' must return a tuple: (response, tool_calls[, context_updates]). Got {type(result)}."
            )
        if len(result) not in (2, 3):
            raise ValueError(
                f"Agent '{agent_name}' must return 2 or 3 items: (response, tool_calls[, context_updates])."
            )
        response, calls, *rest = result
        if not isinstance(response, str):
            raise TypeError(f"Agent '{agent_name}' response must be str, got {type(response)}.")
        if not isinstance(calls, list) or not all(isinstance(c, ToolCall) for c in calls):
            raise TypeError(f"Agent '{agent_name}' tool_calls must be List[ToolCall], got {type(calls)}.")
        updates = rest[0] if rest else {}
        if rest and not isinstance(updates, dict):
            raise TypeError(f"Agent '{agent_name}' context_updates must be dict, got {type(updates)}.")
        if not rest:
            updates = {}
        return response, calls, updates
