from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from environment.sandbox import SandboxManager
from knowledge import Document, KnowledgeManager
from logs.logger import SqliteLogger
from orchestration.runner import EnvironmentRunner
from orchestration.state import AgentState
from tools import ToolRegistry

app = FastAPI(title="HoneyGuard Simulation Environment (HSE)")


@dataclass
class SessionContext:
    session_id: str
    scenario: str
    container_id: str
    runner: EnvironmentRunner
    tools_enabled: List[str]


class InitializeRequest(BaseModel):
    scenario: str = Field(..., description="Name of the scenario to initialize.")
    files: Dict[str, str] = Field(default_factory=dict, description="Files to mount into the sandbox.")
    tools_enabled: List[str] = Field(default_factory=list, description="Tool names to enable for the session.")


class InitializeResponse(BaseModel):
    session_id: str


class RunStepRequest(BaseModel):
    session_id: str
    user_instruction: str


class RunStepResponse(BaseModel):
    agent_response: str
    tool_calls: List[Dict[str, object]]
    trace_id: str


sandbox_manager = SandboxManager()
knowledge_manager = KnowledgeManager()
tool_registry = ToolRegistry(sandbox_manager, knowledge_manager)
logger = SqliteLogger()

SESSIONS: Dict[str, SessionContext] = {}


def _pre_execution_hook(session_id: str):
    def hook(state: AgentState) -> None:
        logger.log_trace(session_id, uuid.uuid4().hex, {"event": "pre_tool_execution", "state": state})

    return hook


def _default_tools(tools_enabled: List[str]) -> List[str]:
    return tools_enabled or ["read_file", "python_repl", "search_knowledge_base"]


@app.post("/v1/environment/initialize", response_model=InitializeResponse)
def initialize_environment(payload: InitializeRequest) -> InitializeResponse:
    session_id = uuid.uuid4().hex
    container_id = sandbox_manager.start(session_id)

    # Mount files into the sandbox and ingest into knowledge base.
    docs: List[Document] = []
    for path, content in payload.files.items():
        sandbox_manager.mount_file(session_id, path, content)
        docs.append(Document(content=content, metadata={"path": path, "scenario": payload.scenario}, doc_id=path))
    if docs:
        knowledge_manager.ingest_documents(docs)

    tools = tool_registry.build(_default_tools(payload.tools_enabled), session_id=session_id)
    runner = EnvironmentRunner(tools=tools, pre_execution_hook=_pre_execution_hook(session_id))

    SESSIONS[session_id] = SessionContext(
        session_id=session_id,
        scenario=payload.scenario,
        container_id=container_id,
        runner=runner,
        tools_enabled=_default_tools(payload.tools_enabled),
    )

    return InitializeResponse(session_id=session_id)


@app.post("/v1/environment/run_step", response_model=RunStepResponse)
def run_step(payload: RunStepRequest) -> RunStepResponse:
    session = SESSIONS.get(payload.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    trace_id = uuid.uuid4().hex
    # Placeholder agent execution; integrate with LLM + tools in future.
    state: AgentState = {
        "messages": [{"role": "user", "content": payload.user_instruction}],
        "scratchpad": "",
        "env_status": {"session_id": payload.session_id, "scenario": session.scenario},
    }
    _ = session.runner.run(state)

    agent_response = f"[stub] Received instruction: {payload.user_instruction}"
    tool_calls: List[Dict[str, object]] = []
    logger.log_trace(
        payload.session_id,
        trace_id,
        {"user_instruction": payload.user_instruction, "agent_response": agent_response, "tool_calls": tool_calls},
    )
    return RunStepResponse(agent_response=agent_response, tool_calls=tool_calls, trace_id=trace_id)
