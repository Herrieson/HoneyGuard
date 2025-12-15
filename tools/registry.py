from __future__ import annotations

from typing import Dict, List, Sequence

from langchain.tools import BaseTool

from environment.sandbox import SandboxManager
from knowledge import KnowledgeManager
from tools.real_tools import BashCommandTool, PythonReplTool, ReadFileTool, SearchKnowledgeBaseTool


class ToolRegistry:
    """Factory for building configured tool lists."""

    def __init__(self, sandbox: SandboxManager, knowledge: KnowledgeManager) -> None:
        self.sandbox = sandbox
        self.knowledge = knowledge
        self._factories = self._default_factories()

    def build(self, tool_names: Sequence[str], session_id: str) -> List[BaseTool]:
        tools: List[BaseTool] = []
        for name in tool_names:
            factory = self._factories.get(name)
            if not factory:
                raise ValueError(f"Tool '{name}' is not registered.")
            tools.append(factory(session_id))
        return tools

    def _default_factories(self) -> Dict[str, callable]:
        return {
            "read_file": lambda session_id: ReadFileTool(self.sandbox, session_id),
            "bash_command": lambda session_id: BashCommandTool(self.sandbox, session_id),
            "python_repl": lambda session_id: PythonReplTool(self.sandbox, session_id),
            "search_knowledge_base": lambda session_id: SearchKnowledgeBaseTool(self.knowledge),
        }
