from __future__ import annotations

import operator
from typing import Annotated, Dict, TypedDict

from langgraph.graph.message import AnyMessage


class AgentState(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]
    scratchpad: str
    env_status: Dict[str, object]
