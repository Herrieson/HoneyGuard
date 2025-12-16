from __future__ import annotations

import uuid
from dataclasses import dataclass
import time
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from environment.sandbox import SandboxManager
from knowledge import Document, KnowledgeManager
from logs.logger import SqliteLogger
from orchestration.agent import SimpleAgent
from orchestration.runner import EnvironmentRunner
from orchestration.state import AgentState
from tools import ToolRegistry

app = FastAPI(title="HoneyGuard Simulation Environment (HSE)")
SESSION_TTL_SECONDS = 30 * 60  # 30 minutes default


@dataclass
class SessionContext:
    session_id: str
    scenario: str
    container_id: str
    runner: EnvironmentRunner
    tools_enabled: List[str]
    tools_by_name: Dict[str, object]
    files: Dict[str, str]
    created_at: float


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
    from config.tool_config import load_tool_config

    cfg = load_tool_config()
    default_list = cfg.get("default_tools") or ["read_file", "python_repl", "search_knowledge_base"]
    allowed = set(cfg.get("allowed_tools") or default_list)
    requested = tools_enabled or default_list
    return [t for t in requested if t in allowed]


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
    tools_by_name = {tool.name: tool for tool in tools}
    runner = EnvironmentRunner(tools=tools, pre_execution_hook=_pre_execution_hook(session_id))

    SESSIONS[session_id] = SessionContext(
        session_id=session_id,
        scenario=payload.scenario,
        container_id=container_id,
        runner=runner,
        tools_enabled=_default_tools(payload.tools_enabled),
        tools_by_name=tools_by_name,
        files=payload.files,
        created_at=time.time(),
    )

    return InitializeResponse(session_id=session_id)


@app.post("/v1/environment/run_step", response_model=RunStepResponse)
def run_step(payload: RunStepRequest) -> RunStepResponse:
    session = SESSIONS.get(payload.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    trace_id = uuid.uuid4().hex
    agent = SimpleAgent(session.tools_by_name, known_files=list(session.files.keys()))
    agent_response, tool_calls_raw = agent.run(payload.user_instruction)

    tool_calls: List[Dict[str, object]] = [
        {"name": call.name, "args": call.args, "output": call.output} for call in tool_calls_raw
    ]
    for call in tool_calls_raw:
        logger.log_tool_call(payload.session_id, trace_id, call.name, call.args, call.output, status="ok")

    logger.log_trace(
        payload.session_id,
        trace_id,
        {"user_instruction": payload.user_instruction, "agent_response": agent_response, "tool_calls": tool_calls},
    )
    return RunStepResponse(agent_response=agent_response, tool_calls=tool_calls, trace_id=trace_id)


@app.delete("/v1/environment/{session_id}")
def cleanup_session(session_id: str) -> Dict[str, str]:
    session = SESSIONS.pop(session_id, None)
    if session:
        sandbox_manager.shutdown(session_id)
    else:
        # Ensure no stray container remains even if session map is missing.
        try:
            sandbox_manager.shutdown(session_id)
        except Exception:
            pass
    return {"status": "ok", "session_id": session_id}


def _cleanup_expired_sessions() -> None:
    now = time.time()
    expired = [sid for sid, ctx in list(SESSIONS.items()) if now - ctx.created_at > SESSION_TTL_SECONDS]
    for sid in expired:
        cleanup_session(sid)


@app.on_event("startup")
async def _startup_tasks() -> None:
    import asyncio

    async def cleaner():
        while True:
            await asyncio.sleep(60)
            _cleanup_expired_sessions()

    # background task for session cleanup
    import asyncio

    loop = asyncio.get_event_loop()
    loop.create_task(cleaner())


@app.on_event("shutdown")
async def _shutdown_tasks() -> None:
    # Cleanup all known sessions
    for sid in list(SESSIONS.keys()):
        cleanup_session(sid)
    # Cleanup any stray containers labeled as HSE
    sandbox_manager.cleanup_all()
