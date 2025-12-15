from __future__ import annotations

from typing import Dict, List, Optional, Type

from pydantic import BaseModel, Field

from knowledge import KnowledgeManager
from langchain.tools import BaseTool


class SearchKnowledgeArgs(BaseModel):
    query: str = Field(..., description="Natural language query to search in the knowledge base.")
    top_k: int = Field(4, description="Number of results to return.")
    metadata_filter: Optional[Dict[str, object]] = Field(
        None, description="Metadata filter used for scoped retrieval."
    )


class SearchKnowledgeBaseTool(BaseTool):
    """Search documents in the knowledge base (RAG)."""

    name: str = "search_knowledge_base"
    description: str = "Search documents in the knowledge base with optional metadata filtering."
    args_schema: Type[BaseModel] = SearchKnowledgeArgs

    def __init__(self, knowledge: KnowledgeManager) -> None:
        super().__init__(name="search_knowledge_base", description="Search documents in the knowledge base with optional metadata filtering.")
        self.knowledge = knowledge

    def _run(self, query: str, top_k: int = 4, metadata_filter: Optional[Dict[str, object]] = None) -> str:
        results = self.knowledge.query(query, top_k=top_k, metadata_filter=metadata_filter)
        if not results:
            return "No matches found."
        lines: List[str] = []
        for item in results:
            meta_repr = item.get("metadata") or {}
            lines.append(f"- {item.get('id')}: {item.get('content')}\n  meta={meta_repr}")
        return "\n".join(lines)

    async def _arun(self, query: str, top_k: int = 4, metadata_filter: Optional[Dict[str, object]] = None) -> str:
        raise NotImplementedError("SearchKnowledgeBaseTool does not support async execution.")
