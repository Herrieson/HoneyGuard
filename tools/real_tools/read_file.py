from __future__ import annotations

import shlex
from typing import Type
from pydantic import BaseModel, Field

from environment.sandbox.manager import SandboxManager
from tools.base import SandboxTool


class ReadFileArgs(BaseModel):
    path: str = Field(..., description="Absolute or relative path to the file inside the sandbox.")


class ReadFileTool(SandboxTool):
    """Read file contents from inside the sandbox container."""

    name: str = "read_file"
    description: str = "Read the contents of a file from within the sandbox container."
    args_schema: Type[BaseModel] = ReadFileArgs

    def __init__(self, sandbox: SandboxManager, session_id: str) -> None:
        super().__init__(sandbox=sandbox, session_id=session_id, name="read_file", description="Read the contents of a file from within the sandbox container.")

    def _run(self, path: str) -> str:
        safe_path = shlex.quote(path)
        result = self.sandbox.execute_command(self.session_id, f"cat {safe_path}")
        if result.exit_code != 0:
            stderr = result.stderr.strip() or "failed to read file"
            return f"[read_file] exit={result.exit_code}: {stderr}"
        return result.stdout

    async def _arun(self, path: str) -> str:
        raise NotImplementedError("ReadFileTool does not support async execution.")
