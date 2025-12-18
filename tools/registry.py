from __future__ import annotations

from typing import Dict, List, Sequence

from langchain.tools import BaseTool

from environment.sandbox import SandboxManager
from knowledge import KnowledgeManager
from tools.real_tools import BashCommandTool, PythonReplTool, ReadFileTool, SearchKnowledgeBaseTool
from tools.mock_tools import MockTool


class ToolRegistry:
    """Factory for building configured tool lists."""

    def __init__(self, sandbox: SandboxManager, knowledge: KnowledgeManager) -> None:
        self.sandbox = sandbox
        self.knowledge = knowledge
        self._factories = self._default_factories()

    def build(self, tool_names: Sequence[str], session_id: str) -> List[BaseTool]:
        tools: List[BaseTool] = []
        for name in tool_names:
            factory = self._factories.get(name) or self._load_factory_from_path(name)
            if not factory:
                raise ValueError(f"Tool '{name}' is not registered.")
            tools.append(factory(session_id))
        return tools

    def register(self, name: str, factory: callable) -> None:
        """Register or override a tool factory at runtime."""
        self._factories[name] = factory

    def register_mocks(self, mock_defs: Sequence[Dict[str, str]]) -> None:
        """Register mock tools from config (each with name/output/optional description)."""
        for item in mock_defs:
            name = item.get("name")
            output = item.get("output")
            desc = item.get("description")
            if not name or output is None:
                continue
            self.register(name, lambda session_id, _n=name, _o=output, _d=desc: MockTool(_n, _o, session_id, _d))

    def _default_factories(self) -> Dict[str, callable]:
        return {
            "read_file": lambda session_id: ReadFileTool(self.sandbox, session_id),
            "bash_command": lambda session_id: BashCommandTool(self.sandbox, session_id),
            "python_repl": lambda session_id: PythonReplTool(self.sandbox, session_id),
            "search_knowledge_base": lambda session_id: SearchKnowledgeBaseTool(self.knowledge, session_id),
        }

    def _load_factory_from_path(self, path: str) -> callable | None:
        """Allow using 'pkg.module:ClassName' directly in tools_enabled."""
        if ":" not in path:
            return None
        try:
            module_path, class_name = path.split(":")
            module = __import__(module_path, fromlist=[class_name])
            tool_cls = getattr(module, class_name)
        except Exception:
            return None

        def _factory(session_id: str):
            try:
                return tool_cls(self.sandbox, session_id)
            except TypeError:
                # Fallback: allow zero-arg constructors for simple tools.
                return tool_cls()

        # Cache so future lookups are fast.
        self._factories[path] = _factory
        return _factory
