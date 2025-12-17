from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from langchain.tools import BaseTool


@dataclass
class ToolCall:
    name: str
    args: Dict[str, object]
    output: Optional[str] = None
    error: Optional[str] = None
    agent: Optional[str] = None
    agent: Optional[str] = None


class SimpleAgent:
    """Rule-based agent to demonstrate tool dispatch without LLM."""

    def __init__(
        self,
        tools_by_name: Dict[str, BaseTool],
        known_files: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
    ) -> None:
        self.tools_by_name = tools_by_name
        self.known_files = known_files or []
        self.system_prompt = system_prompt or ""

    def run(
        self,
        user_instruction: str,
        history: Optional[List[Dict[str, str]]] = None,
        tool_results: Optional[List[Dict[str, object]]] = None,
    ) -> (str, List[ToolCall]):
        # If we already have tool results, summarize instead of issuing new calls.
        if tool_results:
            lines = []
            for item in tool_results:
                name = item.get("name")
                args = item.get("args")
                output = item.get("output") or item.get("error") or ""
                lines.append(f"{name}({args}) => {output}")
            summary = "\n".join(lines) if lines else "No tool results."
            return summary, []

        tool_calls: List[ToolCall] = []
        instruction = user_instruction
        if self.system_prompt:
            instruction = f"{self.system_prompt}\n{user_instruction}"

        # Heuristic: read_file if asked to "read"/"读取" and files are present.
        if self._has_tool("read_file") and self._mentions_read(user_instruction) and self.known_files:
            path = self.known_files[0]
            tool_calls.append(ToolCall(name="read_file", args={"path": path}))

        # Heuristic: search knowledge base if "search"/"查询".
        if self._has_tool("search_knowledge_base") and self._mentions_search(user_instruction):
            tool_calls.append(ToolCall(name="search_knowledge_base", args={"query": user_instruction}))

        # Heuristic: bash_command if pattern "bash: <cmd>" present.
        bash_cmd = self._extract_after_prefix(user_instruction, "bash:")
        if self._has_tool("bash_command") and bash_cmd:
            tool_calls.append(ToolCall(name="bash_command", args={"command": bash_cmd}))

        # Heuristic: python_repl if pattern "python: <code>" present.
        py_code = self._extract_after_prefix(user_instruction, "python:")
        if self._has_tool("python_repl") and py_code:
            tool_calls.append(ToolCall(name="python_repl", args={"code": py_code}))

        if tool_calls:
            response = "Planned tool calls: " + ", ".join(call.name for call in tool_calls)
        else:
            response = f"[stub] Received instruction: {user_instruction}"

        return response, tool_calls

    def _has_tool(self, name: str) -> bool:
        return name in self.tools_by_name

    def _mentions_read(self, text: str) -> bool:
        return bool(re.search(r"(read|读取|查看)", text, re.IGNORECASE))

    def _mentions_search(self, text: str) -> bool:
        return bool(re.search(r"(search|查询|检索)", text, re.IGNORECASE))

    def _extract_after_prefix(self, text: str, prefix: str) -> Optional[str]:
        lowered = text.lower()
        prefix_lower = prefix.lower()
        if prefix_lower in lowered:
            idx = lowered.index(prefix_lower) + len(prefix_lower)
            return text[idx:].strip()
        return None

    def _invoke_tool(self, name: str, args: Dict[str, object]) -> str:
        tool = self.tools_by_name[name]
        try:
            return str(tool.invoke(args))
        except Exception as exc:
            return f"[{name}] error: {exc}"
