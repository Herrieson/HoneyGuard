from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from langchain.tools import BaseTool


@dataclass
class ToolCall:
    name: str
    args: Dict[str, object]
    output: str


class SimpleAgent:
    """Rule-based agent to demonstrate tool dispatch without LLM."""

    def __init__(self, tools_by_name: Dict[str, BaseTool], known_files: Optional[List[str]] = None) -> None:
        self.tools_by_name = tools_by_name
        self.known_files = known_files or []

    def run(self, user_instruction: str) -> (str, List[ToolCall]):
        tool_calls: List[ToolCall] = []

        # Heuristic: read_file if asked to "read"/"读取" and files are present.
        if self._has_tool("read_file") and self._mentions_read(user_instruction) and self.known_files:
            path = self.known_files[0]
            output = self._invoke_tool("read_file", {"path": path})
            tool_calls.append(ToolCall(name="read_file", args={"path": path}, output=output))

        # Heuristic: search knowledge base if "search"/"查询".
        if self._has_tool("search_knowledge_base") and self._mentions_search(user_instruction):
            output = self._invoke_tool("search_knowledge_base", {"query": user_instruction})
            tool_calls.append(ToolCall(name="search_knowledge_base", args={"query": user_instruction}, output=output))

        # Heuristic: bash_command if pattern "bash: <cmd>" present.
        bash_cmd = self._extract_after_prefix(user_instruction, "bash:")
        if self._has_tool("bash_command") and bash_cmd:
            output = self._invoke_tool("bash_command", {"command": bash_cmd})
            tool_calls.append(ToolCall(name="bash_command", args={"command": bash_cmd}, output=output))

        # Heuristic: python_repl if pattern "python: <code>" present.
        py_code = self._extract_after_prefix(user_instruction, "python:")
        if self._has_tool("python_repl") and py_code:
            output = self._invoke_tool("python_repl", {"code": py_code})
            tool_calls.append(ToolCall(name="python_repl", args={"code": py_code}, output=output))

        if tool_calls:
            response = "\n".join([f"{call.name} -> {call.output}" for call in tool_calls])
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
