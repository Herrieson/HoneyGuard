from __future__ import annotations

from abc import ABC
from typing import Optional

from langchain.tools import BaseTool

from environment.sandbox.manager import SandboxManager


class SandboxTool(BaseTool, ABC):
    """A langchain tool that operates inside a sandbox container."""

    sandbox: SandboxManager
    session_id: str

    def __init__(
        self, sandbox: SandboxManager, session_id: str, *, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        super().__init__(sandbox=sandbox, session_id=session_id, name=name, description=description)

    class Config:
        arbitrary_types_allowed = True
