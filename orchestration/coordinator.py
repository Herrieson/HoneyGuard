from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from orchestration.agent import ToolCall


@dataclass
class AgentWrapper:
    name: str
    mode: str
    impl: object


class AgentCoordinator:
    """Multi-agent coordinator with simple patterns."""

    def __init__(
        self,
        agents: Sequence[AgentWrapper],
        pattern: str = "sequential",
        max_cycles: int = 1,
        stop_on_done: bool = True,
        memory_limit: int = 10,
    ) -> None:
        self.agents = list(agents)
        self.pattern = (pattern or "sequential").lower()
        self.max_cycles = max(1, int(max_cycles))
        self.stop_on_done = stop_on_done
        self.memory_limit = max(memory_limit, 1)
        self._memories: dict[str, list[dict]] = {}

    def run(self, user_instruction: str) -> Tuple[str, List[ToolCall]]:
        transcript: List[dict] = []
        tool_calls: List[ToolCall] = []
        stop = False

        if self.pattern == "round_robin":
            for _ in range(self.max_cycles):
                for agent in self.agents:
                    prompt = self._build_prompt(user_instruction, transcript)
                    response, calls = agent.impl.run(prompt, history=self._memory_for(agent.name))
                    self._record(agent.name, response)
                    transcript.append({"agent": agent.name, "content": response})
                    self._append_calls(tool_calls, calls, agent.name)
                    if self.stop_on_done and self._is_done(response):
                        stop = True
                        break
                if stop:
                    break
        elif self.pattern == "parallel":
            prompt = self._build_prompt(user_instruction, transcript)
            for agent in self.agents:
                response, calls = agent.impl.run(prompt, history=self._memory_for(agent.name))
                self._record(agent.name, response)
                transcript.append({"agent": agent.name, "content": response})
                self._append_calls(tool_calls, calls, agent.name)
        elif self.pattern == "planner_executor_verifier" and len(self.agents) >= 2:
            planner = self.agents[0]
            executor = self.agents[1]
            verifier = self.agents[2] if len(self.agents) > 2 else None

            # Planner step
            plan_prompt = self._build_prompt(user_instruction, transcript)
            plan_resp, plan_calls = planner.impl.run(plan_prompt, history=self._memory_for(planner.name))
            self._record(planner.name, plan_resp)
            transcript.append({"agent": planner.name, "content": plan_resp})
            self._append_calls(tool_calls, plan_calls, planner.name)
            if self.stop_on_done and self._is_done(plan_resp):
                stop = True

            # Executor step(s)
            if not stop:
                exec_prompt = self._build_prompt(plan_resp, transcript)
                exec_resp, exec_calls = executor.impl.run(exec_prompt, history=self._memory_for(executor.name))
                self._record(executor.name, exec_resp)
                transcript.append({"agent": executor.name, "content": exec_resp})
                self._append_calls(tool_calls, exec_calls, executor.name)
                if self.stop_on_done and self._is_done(exec_resp):
                    stop = True

            # Verifier step (optional)
            if verifier and not stop:
                ver_prompt = self._build_prompt(exec_resp, transcript)
                ver_resp, ver_calls = verifier.impl.run(ver_prompt, history=self._memory_for(verifier.name))
                self._record(verifier.name, ver_resp)
                transcript.append({"agent": verifier.name, "content": ver_resp})
                self._append_calls(tool_calls, ver_calls, verifier.name)
        else:  # sequential default
            for agent in self.agents:
                prompt = self._build_prompt(user_instruction, transcript)
                response, calls = agent.impl.run(prompt, history=self._memory_for(agent.name))
                self._record(agent.name, response)
                transcript.append({"agent": agent.name, "content": response})
                self._append_calls(tool_calls, calls, agent.name)
                if self.stop_on_done and self._is_done(response):
                    break

        final_response = "\n".join(f"{m['agent']}: {m['content']}" for m in transcript) if transcript else ""
        return final_response, tool_calls

    def _build_prompt(self, user_instruction: str, transcript: List[dict]) -> str:
        if not transcript:
            return user_instruction
        history = "\n".join(f"{m['agent']}: {m['content']}" for m in transcript)
        return f"{user_instruction}\n\nContext from previous agents:\n{history}"

    def _append_calls(self, tool_calls: List[ToolCall], calls: List[ToolCall], agent_name: str) -> None:
        for call in calls:
            call.agent = agent_name
            tool_calls.append(call)

    def _record(self, agent_name: str, content: str) -> None:
        history = self._memories.setdefault(agent_name, [])
        history.append({"agent": agent_name, "content": content})
        if len(history) > self.memory_limit:
            del history[0 : len(history) - self.memory_limit]

    def _memory_for(self, agent_name: str) -> List[dict]:
        return list(self._memories.get(agent_name, []))

    def _is_done(self, text: str) -> bool:
        return "done" in text.lower()
