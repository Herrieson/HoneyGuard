from __future__ import annotations

from typing import Optional, Type

from pydantic import BaseModel, Field

from environment.sandbox import SandboxManager
from tools.base import SandboxTool


class PythonReplArgs(BaseModel):
    code: str = Field(..., description="Python code to execute inside the sandbox container.")
    workdir: Optional[str] = Field(None, description="Working directory inside the sandbox.")


class PythonReplTool(SandboxTool):
    """Run Python snippets inside the sandbox container."""

    name: str = "python_repl"
    description: str = "Execute Python code inside the sandboxed container."
    args_schema: Type[BaseModel] = PythonReplArgs

    def __init__(self, sandbox: SandboxManager, session_id: str) -> None:
        super().__init__(sandbox=sandbox, session_id=session_id, name="python_repl", description="Execute Python code inside the sandboxed container.")

    def _run(self, code: str, workdir: Optional[str] = None) -> str:
        command = "python - <<'PY'\n" + code + "\nPY"
        result = self.sandbox.execute_command(self.session_id, command, workdir=workdir)
        output_parts = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append(f"[stderr]\n{result.stderr}")

        combined_output = "\n".join(part for part in output_parts if part)
        if result.exit_code != 0:
            return f"[python_repl] exit={result.exit_code}\n{combined_output}"
        return combined_output or "(no output)"

    async def _arun(self, code: str, workdir: Optional[str] = None) -> str:
        raise NotImplementedError("PythonReplTool does not support async execution.")
