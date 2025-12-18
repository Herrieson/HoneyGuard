from __future__ import annotations

import uuid
from dataclasses import dataclass
import time
from typing import Any, Dict, List, Optional, Tuple, Literal
import os
import logging
import shlex

from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel, Field

from environment.sandbox import SandboxManager
from knowledge import Document, KnowledgeManager
from logs.logger import SqliteLogger
from orchestration.agent import SimpleAgent
from orchestration.runner import EnvironmentRunner
from orchestration.state import AgentState
from orchestration.coordinator import AgentCoordinator, AgentWrapper
from orchestration import policy
from tools import ToolRegistry

app = FastAPI(title="HoneyGuard Simulation Environment (HSE)")
SESSION_TTL_SECONDS = 30 * 60  # 30 minutes default
API_TOKEN = None
RATE_WINDOW = 60  # seconds
RATE_LIMIT = 60  # requests per IP per window
_RATE_STATE: Dict[str, Tuple[float, int]] = {}


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
    agent_mode: str
    agent: object
    agents: List[AgentWrapper]
    coordinator: AgentCoordinator
    coordination_pattern: str
    memory_limit: int
    max_steps: int
    queued_instructions: List[str]
    instruction_cursor: int
    graph_template: Optional[str]
    stop_signals: List[str]
    max_elapsed_sec: Optional[float]
    shared_context: Dict[str, object]
    acceptance_criteria: List["AcceptanceCriterion"]
    acceptance_logic: str
    acceptance_baseline: Dict[str, str]


class AgentConfig(BaseModel):
    name: str = Field(..., description="Agent name/role.")
    mode: str = Field("rule", description="Agent mode: 'rule' or 'llm'.")
    system_prompt: Optional[str] = Field(None, description="Optional system prompt for the agent.")
    tools_allowed: Optional[List[str]] = Field(
        None, description="Subset of tools this agent may use. Defaults to all enabled tools."
    )
    impl: Optional[str] = Field(
        None,
        description="Optional import path for custom agent, e.g., 'mypkg.agent:MyAgent'. Overrides mode if set.",
    )
    tool_timeout_sec: Optional[int] = Field(
        None, description="Optional per-agent tool timeout seconds (applied per tool call if supported)."
    )
    llm_config: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional LLM config for this agent (provider/model/api_key/base_url/api_version/deployment_name). Overrides global llm_config.",
    )
    memory_limit: Optional[int] = Field(
        5, description="Optional per-agent memory size (number of past messages to retain)."
    )
    memory_mode: str = Field("window", description="Memory strategy: 'window' (default) or 'none'.")
    blackboard_read_keys: Optional[List[str]] = Field(
        None, description="Allowed shared_context keys to read (use ['*'] for all). Defaults to all."
    )
    blackboard_write_keys: Optional[List[str]] = Field(
        None, description="Allowed shared_context keys to write (use ['*'] for all). Defaults to all."
    )

    def normalized_mode(self) -> str:
        mode = (self.mode or "rule").lower()
        if mode not in {"rule", "llm"}:
            raise ValueError("agent mode must be 'rule' or 'llm'")
        return mode


class AcceptanceCriterion(BaseModel):
    """Acceptance rule evaluated after each run_step."""

    type: Literal[
        "response_contains",
        "tool_output_contains",
        "shared_context_equals",
        "file_contains",
        "file_not_contains",
        "file_hash_equals",
        "file_changed",
        "command_exit_code",
        "command_output_contains",
    ] = Field(..., description="Criterion type.")
    value: str = Field(..., description="String to match or expected value (hash/substring/command arg).")
    key: Optional[str] = Field(
        None,
        description="For shared_context_equals, the key to compare.",
    )
    path: Optional[str] = Field(
        None,
        description="For file-based checks, the path inside the sandbox.",
    )
    expect_exit_code: Optional[int] = Field(
        None,
        description="For command_exit_code, expected exit code (default 0).",
    )
    command: Optional[str] = Field(
        None,
        description="For command checks, the command to run inside the sandbox.",
    )


class InitializeRequest(BaseModel):
    scenario: str = Field(..., description="Name of the scenario to initialize.")
    files: Dict[str, str] = Field(default_factory=dict, description="Files to mount into the sandbox.")
    tools_enabled: List[str] = Field(default_factory=list, description="Tool names to enable for the session.")
    agent_mode: str = Field("rule", description="Agent mode: 'rule' (default) or 'llm'.")
    agents: List[AgentConfig] = Field(
        default_factory=list,
        description="Optional multi-agent definition; if provided, overrides agent_mode.",
    )
    coordination_pattern: str = Field(
        "sequential",
        description="Coordinator pattern for multi-agent: 'sequential' (default) or 'round_robin'.",
    )
    max_cycles: int = Field(
        1,
        description="For round_robin, how many cycles to run (>=1). Ignored for sequential.",
    )
    llm_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional LLM provider settings (provider, model, api_key, base_url, api_version, deployment_name).",
    )
    memory_limit: int = Field(10, description="Per-agent memory size (number of past messages retained).")
    max_steps: int = Field(3, description="Max graph steps before termination.")
    initial_instructions: List[str] = Field(
        default_factory=list,
        description="Optional queued user instructions; used in order when run_step is called without user_instruction.",
    )
    graph_template: Optional[str] = Field(
        None,
        description="Optional graph template name or import path (module:function) returning a compiled LangGraph app.",
    )
    stop_signals: List[str] = Field(
        default_factory=lambda: ["done"],
        description="Strings that will trigger early termination when found in agent responses (case-insensitive).",
    )
    max_elapsed_sec: Optional[float] = Field(
        None,
        description="Optional cumulative tool execution time budget in seconds; run will stop when exceeded.",
    )
    shared_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional initial shared blackboard (key-value) visible to agents with read access.",
    )
    acceptance_criteria: List[AcceptanceCriterion] = Field(
        default_factory=list,
        description="Optional list of acceptance rules evaluated after each run_step.",
    )
    acceptance_logic: Literal["all", "any"] = Field(
        "all",
        description="Whether all criteria must pass ('all') or any one is sufficient ('any').",
    )


class InitializeResponse(BaseModel):
    session_id: str


class RunStepRequest(BaseModel):
    session_id: str
    user_instruction: Optional[str] = Field(
        None, description="User instruction for this step; if omitted, falls back to queued initial_instructions."
    )


class RunStepResponse(BaseModel):
    agent_response: str
    tool_calls: List[Dict[str, object]]
    trace_id: str
    acceptance_passed: Optional[bool] = Field(
        None, description="Whether all acceptance criteria passed (if configured)."
    )
    acceptance_results: Optional[List[Dict[str, object]]] = Field(
        None, description="Per-criterion evaluation results when acceptance criteria are configured."
    )


sandbox_manager = SandboxManager()
knowledge_manager = KnowledgeManager()
tool_registry = ToolRegistry(sandbox_manager, knowledge_manager)
logger = SqliteLogger()
log = logging.getLogger(__name__)

SESSIONS: Dict[str, SessionContext] = {}


def _check_auth_and_rate(request: Request) -> None:
    global API_TOKEN
    client_id = request.client.host if request.client else "unknown"
    token = request.headers.get("X-API-Token")
    if API_TOKEN is None:
        API_TOKEN = os.getenv("HSE_API_TOKEN")
    if API_TOKEN:
        if token != API_TOKEN:
            raise HTTPException(status_code=401, detail="Unauthorized")

    now = time.time()
    window_start, count = _RATE_STATE.get(client_id, (now, 0))
    if now - window_start > RATE_WINDOW:
        window_start, count = now, 0
    count += 1
    if count > RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _RATE_STATE[client_id] = (window_start, count)


def _pre_execution_hook(session_id: str):
    def hook(state: AgentState) -> None:
        logger.log_trace(session_id, uuid.uuid4().hex, {"event": "pre_tool_execution", "state": state})

    return hook


def _file_hash(session_id: str, path: str) -> Optional[str]:
    result = sandbox_manager.execute_command(session_id, f"sha256sum {shlex.quote(path)}")
    if result.exit_code != 0 or not result.stdout:
        return None
    return result.stdout.split()[0]


def _read_file(session_id: str, path: str) -> Optional[str]:
    result = sandbox_manager.execute_command(session_id, f"cat {shlex.quote(path)}")
    if result.exit_code != 0:
        return None
    return result.stdout


def _run_command(session_id: str, command: str) -> Tuple[int, str]:
    result = sandbox_manager.execute_command(session_id, command)
    output_parts = []
    if result.stdout:
        output_parts.append(result.stdout)
    if result.stderr:
        output_parts.append(f"[stderr]\n{result.stderr}")
    return result.exit_code, "\n".join(output_parts)


def _capture_acceptance_baseline(session_id: str, criteria: List["AcceptanceCriterion"]) -> Dict[str, str]:
    baseline: Dict[str, str] = {}
    for crit in criteria:
        if crit.type == "file_changed" and crit.path:
            h = _file_hash(session_id, crit.path)
            if h:
                baseline[crit.path] = h
    return baseline


def _evaluate_acceptance(
    session_id: str,
    criteria: List["AcceptanceCriterion"],
    logic: str,
    agent_response: str,
    tool_calls: List[Dict[str, object]],
    shared_context: Dict[str, object],
    baseline: Dict[str, str],
) -> Tuple[bool, List[Dict[str, object]]]:
    """Evaluate configured acceptance criteria after a step."""
    results: List[Dict[str, object]] = []
    tool_outputs = []
    for call in tool_calls:
        if call.get("output"):
            tool_outputs.append(str(call.get("output")))
        if call.get("error"):
            tool_outputs.append(str(call.get("error")))
    tool_text = "\n".join(tool_outputs)

    for crit in criteria:
        passed = False
        detail = ""
        value = crit.value or ""
        if crit.type == "response_contains":
            passed = value.lower() in (agent_response or "").lower()
            detail = "matched agent_response" if passed else "not found in agent_response"
        elif crit.type == "tool_output_contains":
            passed = value.lower() in tool_text.lower()
            detail = "matched tool output" if passed else "not found in tool outputs"
        elif crit.type == "shared_context_equals":
            key = crit.key or ""
            expected = str(value)
            actual = str(shared_context.get(key, ""))
            passed = key in shared_context and actual == expected
            detail = f"shared_context[{key}] == {expected}" if passed else f"shared_context[{key}] != {expected}"
        elif crit.type in {"file_contains", "file_not_contains", "file_hash_equals", "file_changed"}:
            if not crit.path:
                detail = "path not provided"
            else:
                content = _read_file(session_id, crit.path) if crit.type in {"file_contains", "file_not_contains"} else None
                if crit.type == "file_contains":
                    if content is None:
                        detail = "failed to read file"
                    else:
                        passed = value in content
                        detail = "found in file" if passed else "not found in file"
                elif crit.type == "file_not_contains":
                    if content is None:
                        detail = "failed to read file"
                    else:
                        passed = value not in content
                        detail = "absent from file" if passed else "value present in file"
                elif crit.type == "file_hash_equals":
                    h = _file_hash(session_id, crit.path)
                    if h is None:
                        detail = "failed to hash file"
                    else:
                        passed = h == value
                        detail = "hash matched" if passed else f"hash mismatch: {h}"
                elif crit.type == "file_changed":
                    prev = baseline.get(crit.path)
                    current = _file_hash(session_id, crit.path)
                    if prev is None or current is None:
                        detail = "baseline or current hash unavailable"
                    else:
                        passed = prev != current
                        detail = "file changed" if passed else "file unchanged"
        elif crit.type in {"command_exit_code", "command_output_contains"}:
            cmd = crit.command or crit.value
            if not cmd:
                detail = "command not provided"
            else:
                exit_code, output = _run_command(session_id, cmd)
                if crit.type == "command_exit_code":
                    expected = crit.expect_exit_code if crit.expect_exit_code is not None else 0
                    passed = exit_code == expected
                    detail = f"exit {exit_code}, expected {expected}"
                else:
                    passed = value.lower() in output.lower()
                    detail = "found in command output" if passed else "not found in command output"
        results.append(
            {
                "type": crit.type,
                "key": crit.key,
                "path": crit.path,
                "value": crit.value,
                "passed": passed,
                "detail": detail,
            }
        )
    if not results:
        return True, results
    overall = all(item["passed"] for item in results) if logic == "all" else any(
        item["passed"] for item in results
    )
    return overall, results


def _default_tools(tools_enabled: List[str]) -> List[str]:
    from config.tool_config import load_tool_config

    cfg = load_tool_config()
    default_list = cfg.get("default_tools") or ["read_file", "python_repl", "search_knowledge_base"]
    allowed = set(cfg.get("allowed_tools") or default_list)
    requested = tools_enabled or default_list
    return [t for t in requested if t in allowed]


def _load_custom_agent(impl_path: str, tools_by_name: Dict[str, object], known_files: List[str], system_prompt: Optional[str]):
    try:
        module_path, class_name = impl_path.split(":")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent impl path: {impl_path}") from exc

    try:
        module = __import__(module_path, fromlist=[class_name])
        agent_cls = getattr(module, class_name)
        return agent_cls(tools_by_name, known_files=known_files, system_prompt=system_prompt)
    except Exception as exc:  # pragma: no cover - dynamic import errors
        log.exception("Failed to load custom agent %s", impl_path)
        raise HTTPException(status_code=500, detail=f"Failed to load custom agent {impl_path}: {exc}") from exc


def _build_agent(agent_mode: str, tools_by_name: Dict[str, object], known_files: List[str]):
    return _build_agent_with_options(agent_mode, tools_by_name, known_files, system_prompt=None)


def _build_agent_with_options(
    agent_mode: str,
    tools_by_name: Dict[str, object],
    known_files: List[str],
    system_prompt: Optional[str],
    impl: Optional[str] = None,
    llm_config: Optional[Dict[str, Any]] = None,
):
    if impl:
        agent = _load_custom_agent(impl, tools_by_name, known_files, system_prompt)
        if agent:
            return agent

    mode = (agent_mode or "rule").lower()
    if mode == "llm":
        try:
            from orchestration.llm_agent import LLMAgent
        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail="LLM agent dependencies are missing. Install langchain-openai and set OPENAI_API_KEY.",
            ) from exc
        try:
            return LLMAgent(
                list(tools_by_name.values()),
                known_files=known_files,
                system_prompt=system_prompt,
                llm_config=llm_config or {},
            )
        except Exception as exc:  # pragma: no cover - runtime initialization errors
            raise HTTPException(status_code=500, detail=f"Failed to initialize LLM agent: {exc}") from exc
    # Default: rule-based agent
    return SimpleAgent(tools_by_name, known_files=known_files, system_prompt=system_prompt)


def _build_agents(
    agent_configs: List[AgentConfig],
    fallback_mode: str,
    tools_by_name: Dict[str, object],
    known_files: List[str],
    llm_config: Dict[str, Any],
) -> List[AgentWrapper]:
    if agent_configs:
        configs = agent_configs
    else:
        configs = [AgentConfig(name="agent", mode=fallback_mode)]

    agents: List[AgentWrapper] = []
    for cfg in configs:
        mode = cfg.normalized_mode()
        allowed = cfg.tools_allowed or list(tools_by_name.keys())
        filtered_tools = {k: v for k, v in tools_by_name.items() if k in allowed}
        impl = _build_agent_with_options(
            mode,
            filtered_tools,
            known_files,
            cfg.system_prompt,
            cfg.impl,
            cfg.llm_config or llm_config,
        )
        agents.append(
            AgentWrapper(
                name=cfg.name,
                mode=mode,
                impl=impl,
                memory_mode=(cfg.memory_mode or "window").lower(),
                blackboard_read_keys=cfg.blackboard_read_keys or ["*"],
                blackboard_write_keys=cfg.blackboard_write_keys or ["*"],
            )
        )
    return agents


@app.post("/v1/environment/initialize", response_model=InitializeResponse)
def initialize_environment(payload: InitializeRequest, _: None = Depends(_check_auth_and_rate)) -> InitializeResponse:
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
    agents = _build_agents(
        payload.agents,
        payload.agent_mode,
        tools_by_name,
        known_files=list(payload.files.keys()),
        llm_config=payload.llm_config,
    )
    acceptance_baseline = _capture_acceptance_baseline(session_id, payload.acceptance_criteria)
    coordinator = AgentCoordinator(
        agents,
        pattern=(payload.coordination_pattern or "sequential"),
        max_cycles=payload.max_cycles or 1,
        stop_on_done=True,
        memory_limit=payload.memory_limit,
        stop_signals=payload.stop_signals,
    )
    try:
        runner = EnvironmentRunner(
            coordinator=coordinator,
            pre_execution_hook=_pre_execution_hook(session_id),
            tools_by_name=tools_by_name,
            max_steps=payload.max_steps,
            stop_on_done=True,
            graph_template=payload.graph_template,
            stop_signals=payload.stop_signals,
            max_elapsed_sec=payload.max_elapsed_sec,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("Failed to build EnvironmentRunner for session %s", session_id)
        raise HTTPException(status_code=500, detail=f"Failed to build EnvironmentRunner: {exc}") from exc
    policy.reset_session(session_id)

    SESSIONS[session_id] = SessionContext(
        session_id=session_id,
        scenario=payload.scenario,
        container_id=container_id,
        runner=runner,
        tools_enabled=_default_tools(payload.tools_enabled),
        tools_by_name=tools_by_name,
        files=payload.files,
        created_at=time.time(),
        agent_mode=payload.agent_mode,
        agent=agents[0].impl if agents else None,
        agents=agents,
        coordinator=coordinator,
        coordination_pattern=payload.coordination_pattern,
        memory_limit=payload.memory_limit,
        max_steps=payload.max_steps,
        queued_instructions=list(payload.initial_instructions or []),
        instruction_cursor=0,
        graph_template=payload.graph_template,
        stop_signals=payload.stop_signals,
        max_elapsed_sec=payload.max_elapsed_sec,
        shared_context=dict(payload.shared_context or {}),
        acceptance_criteria=list(payload.acceptance_criteria or []),
        acceptance_logic=payload.acceptance_logic or "all",
        acceptance_baseline=acceptance_baseline,
    )

    return InitializeResponse(session_id=session_id)


@app.post("/v1/environment/run_step", response_model=RunStepResponse)
def run_step(payload: RunStepRequest, _: None = Depends(_check_auth_and_rate)) -> RunStepResponse:
    session = SESSIONS.get(payload.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    instruction = payload.user_instruction
    if instruction is None or instruction.strip() == "":
        if session.instruction_cursor < len(session.queued_instructions):
            instruction = session.queued_instructions[session.instruction_cursor]
            session.instruction_cursor += 1
        else:
            raise HTTPException(status_code=400, detail="user_instruction is required when no queued instructions remain")

    trace_id = uuid.uuid4().hex
    state: AgentState = {
        "input": instruction,
        "env_status": {},
        "tool_results": [],
        "shared_context": session.shared_context if session else {},
    }
    try:
        result = session.runner.run(state)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Agent execution error: {exc}") from exc
    except Exception as exc:
        log.exception("Agent execution failed for session %s", payload.session_id)
        raise HTTPException(status_code=500, detail=f"Agent execution failed: {exc}") from exc
    tool_calls_raw = result.get("last_tool_calls") or []
    agent_response = result.get("last_response", "")
    session.shared_context = result.get("shared_context") or session.shared_context

    tool_calls: List[Dict[str, object]] = []
    for call in tool_calls_raw:
        entry = {
            "name": call.get("name"),
            "args": call.get("args"),
            "output": call.get("output"),
            "error": call.get("error"),
            "elapsed_sec": call.get("elapsed_sec"),
            "status": call.get("status") or ("error" if call.get("error") else "ok"),
            "agent": call.get("agent"),
        }
        tool_calls.append(entry)
        args_with_agent = dict(call.get("args") or {})
        if call.get("agent"):
            args_with_agent["_agent"] = call.get("agent")
        logger.log_tool_call(
            payload.session_id,
            trace_id,
            call.get("name", ""),
            args_with_agent,
            call.get("output", "") or call.get("error", ""),
            status=entry["status"],
        )

    acceptance_passed: Optional[bool] = None
    acceptance_results: Optional[List[Dict[str, object]]] = None
    if session.acceptance_criteria:
        acceptance_passed, acceptance_results = _evaluate_acceptance(
            session.session_id,
            session.acceptance_criteria,
            session.acceptance_logic,
            agent_response,
            tool_calls,
            session.shared_context,
            session.acceptance_baseline,
        )

    logger.log_trace(
        payload.session_id,
        trace_id,
        {
            "user_instruction": payload.user_instruction,
            "agent_response": agent_response,
            "tool_calls": tool_calls,
            "acceptance_passed": acceptance_passed,
            "acceptance_results": acceptance_results,
        },
    )
    return RunStepResponse(
        agent_response=agent_response,
        tool_calls=tool_calls,
        trace_id=trace_id,
        acceptance_passed=acceptance_passed,
        acceptance_results=acceptance_results,
    )


@app.delete("/v1/environment/{session_id}")
def cleanup_session(session_id: str, _: None = Depends(_check_auth_and_rate)) -> Dict[str, str]:
    session = SESSIONS.pop(session_id, None)
    if session:
        sandbox_manager.shutdown(session_id)
        policy.cleanup_session(session_id)
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
        log_retention_days = int(os.getenv("HSE_LOG_RETENTION_DAYS", "7"))
        while True:
            await asyncio.sleep(60)
            _cleanup_expired_sessions()
            logger.prune(log_retention_days)
            sandbox_manager.cleanup_all()

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


@app.get("/health")
def health(_: None = Depends(_check_auth_and_rate)) -> Dict[str, Any]:
    return {
        "status": "ok",
        "sessions": len(SESSIONS),
        "rate_limit": RATE_LIMIT,
        "token_required": bool(API_TOKEN or os.getenv("HSE_API_TOKEN")),
    }


@app.post("/admin/cleanup_containers")
def cleanup_containers(_: None = Depends(_check_auth_and_rate)) -> Dict[str, str]:
    sandbox_manager.cleanup_all()
    return {"status": "ok", "action": "cleanup_containers"}
