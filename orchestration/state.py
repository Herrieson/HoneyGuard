from __future__ import annotations

import operator
from typing import Annotated, Dict, TypedDict

from langgraph.graph.message import AnyMessage


class AgentState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], operator.add]
    scratchpad: str
    env_status: Dict[str, object]
    input: str
    last_response: str
    last_tool_calls: list[Dict[str, object]]
    pending_tool_calls: list[Dict[str, object]]
    tool_results: list[Dict[str, object]]
