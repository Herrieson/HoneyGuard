from __future__ import annotations

import base64
import importlib.util
import os
import shlex
from typing import Dict, List, Sequence, Optional
from pathlib import Path
import json
import textwrap

from langchain.tools import BaseTool
from pydantic import BaseModel

from environment.sandbox import SandboxManager
from knowledge import KnowledgeManager
from tools.real_tools import BashCommandTool, PythonReplTool, ReadFileTool, SearchKnowledgeBaseTool
from tools.mock_tools import MockTool
from tools.base import SandboxTool
from orchestration.policy import enforce_tool_quota
from config.tool_config import get_default_limits


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

    def _load_factory_from_path(self, path: str) -> Optional[callable]:
        """Allow using 'pkg.module:ClassName' directly in tools_enabled, gated and executed inside container."""
        if ":" not in path:
            return None

        allow_dynamic = os.getenv("HSE_ALLOW_DYNAMIC_TOOLS", "true").lower() in {"1", "true", "yes"}
        if not allow_dynamic:
            raise ValueError(
                f"Dynamic tool import '{path}' denied: set HSE_ALLOW_DYNAMIC_TOOLS=true to enable container execution."
            )

        try:
            module_path, class_name = path.split(":")
        except ValueError:
            raise ValueError(f"Invalid tool path format (expected pkg.module:ClassName): {path}")

        spec = importlib.util.find_spec(module_path)
        if not spec or not spec.origin:
            raise ValueError(f"Cannot locate module '{module_path}' for dynamic tool.")
        source_path = Path(spec.origin)
        if not source_path.exists():
            raise ValueError(f"Module file not found for dynamic tool: {source_path}")

        # Dynamic tool wrapper that copies source into the sandbox and executes inside the container.
        class DynamicToolArgs(BaseModel):
            class Config:
                extra = "allow"

        class DynamicContainerTool(SandboxTool):
            name: str = path
            description: str = f"Dynamic tool executed inside sandbox: {path}"
            args_schema = DynamicToolArgs

            def __init__(self, sandbox: SandboxManager, session_id: str) -> None:
                super().__init__(sandbox=sandbox, session_id=session_id, name=path, description=self.description)
                # Copy source into container under /tmp/hse_dynamic_tools
                rel_module_path = Path(*module_path.split("."))  # convert dots to path segments
                container_dir = Path("/tmp/hse_dynamic_tools") / rel_module_path.parent
                container_dir_str = shlex.quote(str(container_dir))
                if container_dir_str:
                    self.sandbox.execute_command(session_id, f"mkdir -p {container_dir_str}")
                self.container_module_path = str(Path("/tmp/hse_dynamic_tools") / rel_module_path) + ".py"
                self.sandbox.mount_file(session_id, self.container_module_path, source_path.read_text())

            def _run(self, **kwargs):
                enforce_tool_quota(self.session_id)
                limits = get_default_limits()
                payload = json.dumps(kwargs or {})
                b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
                code = textwrap.dedent(
                    f"""
                    import base64, json, importlib.util
                    data = json.loads(base64.b64decode("{b64}").decode("utf-8"))
                    spec = importlib.util.spec_from_file_location("{module_path}", "{self.container_module_path}")
                    if spec is None or spec.loader is None:
                        raise RuntimeError("failed to load dynamic tool {module_path}:{class_name}")
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    cls = getattr(mod, "{class_name}")
                    target = cls()
                    if hasattr(target, "run"):
                        result = target.run(**data)
                    elif callable(target):
                        result = target(**data)
                    elif hasattr(target, "_run"):
                        result = target._run(**data)
                    else:
                        raise RuntimeError("dynamic tool has no callable entrypoint")
                    print("" if result is None else result)
                    """
                ).strip()
                command = f"python - <<'PY'\n{code}\nPY"
                result = self.sandbox.execute_command(
                    self.session_id,
                    command,
                    timeout_sec=limits.get("timeout_sec"),
                    cpu_limit=limits.get("cpu_limit"),
                    mem_limit=limits.get("mem_limit"),
                )
                output_parts = []
                if result.stdout:
                    output_parts.append(result.stdout)
                if result.stderr:
                    output_parts.append(f"[stderr]\n{result.stderr}")
                combined = "\n".join(part for part in output_parts if part)
                if result.exit_code != 0:
                    return f"[dynamic_tool] exit={result.exit_code}\n{combined}"
                return combined or "(no output)"

            async def _arun(self, **kwargs):
                raise NotImplementedError("DynamicContainerTool does not support async execution.")

        def _factory(session_id: str):
            return DynamicContainerTool(self.sandbox, session_id)

        # Cache so future lookups are fast.
        self._factories[path] = _factory
        return _factory
