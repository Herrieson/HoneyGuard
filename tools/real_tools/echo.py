from __future__ import annotations

from typing import Type
from pydantic import BaseModel, Field

from tools.base import SandboxTool


class EchoArgs(BaseModel):
    message: str = Field(..., description="Message to echo back.")


class EchoTool(SandboxTool):
    """Minimal example tool to demonstrate custom tool registration."""

    name: str = "echo"
    description: str = "Return the provided message; useful as a template for new tools."
    args_schema: Type[BaseModel] = EchoArgs

    def __init__(self, sandbox, session_id: str) -> None:
        super().__init__(sandbox=sandbox, session_id=session_id, name=self.name, description=self.description)

    def _run(self, message: str) -> str:  # pragma: no cover - example tool
        return message

    async def _arun(self, message: str) -> str:
        raise NotImplementedError("EchoTool does not support async execution.")
