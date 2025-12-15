from __future__ import annotations

from typing import Optional, Type

from pydantic import BaseModel, Field

from environment.sandbox.manager import SandboxManager
from tools.base import SandboxTool


class BashCommandArgs(BaseModel):
    command: str = Field(..., description="Shell command to run inside the sandbox.")
    workdir: Optional[str] = Field(None, description="Working directory inside the container.")


class BashCommandTool(SandboxTool):
    """Execute bash commands within the sandbox container."""

    name: str = "bash_command"
    description: str = "Execute an arbitrary bash command inside the sandbox container."
    args_schema: Type[BaseModel] = BashCommandArgs

    def __init__(self, sandbox: SandboxManager, session_id: str) -> None:
        super().__init__(sandbox=sandbox, session_id=session_id, name="bash_command", description="Execute an arbitrary bash command inside the sandbox container.")

    def _run(self, command: str, workdir: Optional[str] = None) -> str:
        result = self.sandbox.execute_command(self.session_id, command, workdir=workdir)
        output_parts = []
        if result.stdout:
            output_parts.append(result.stdout)
        if result.stderr:
            output_parts.append(f"[stderr]\n{result.stderr}")

        combined_output = "\n".join(part for part in output_parts if part)
        if result.exit_code != 0:
            return f"[bash_command] exit={result.exit_code}\n{combined_output}"
        return combined_output or "(no output)"

    async def _arun(self, command: str, workdir: Optional[str] = None) -> str:
        raise NotImplementedError("BashCommandTool does not support async execution.")
