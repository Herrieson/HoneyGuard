from __future__ import annotations

from typing import Type

from langchain.tools import BaseTool
from pydantic import BaseModel, Field

from orchestration.policy import enforce_tool_quota


class MockToolArgs(BaseModel):
    """No-op args placeholder to satisfy LangChain interface."""

    dummy: str | None = Field(None, description="Unused placeholder argument.")


class MockTool(BaseTool):
    """A simple tool that returns a preconfigured string output."""

    name: str
    description: str
    session_id: str
    args_schema: Type[BaseModel] = MockToolArgs

    def __init__(self, name: str, output: str, session_id: str, description: str | None = None) -> None:
        super().__init__(name=name, description=description or f"Mock tool that returns '{output}'", session_id=session_id)
        self._output = output

    def _run(self, dummy: str | None = None) -> str:
        enforce_tool_quota(self.session_id)
        return self._output

    async def _arun(self, dummy: str | None = None) -> str:
        raise NotImplementedError("MockTool does not support async execution.")

    class Config:
        arbitrary_types_allowed = True
