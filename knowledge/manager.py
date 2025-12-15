from __future__ import annotations

from typing import Any, Dict, List, Optional

from knowledge.document_loader.loader import Document
from knowledge.vector_store.chroma_store import ChromaVectorStore


class KnowledgeManager:
    """Manage ingestion and retrieval over the knowledge base."""

    def __init__(self, vector_store: Optional[ChromaVectorStore] = None) -> None:
        self.vector_store = vector_store or ChromaVectorStore()

    def ingest_documents(self, docs: List[Document]) -> None:
        texts = [doc.content for doc in docs]
        metadatas = [doc.metadata for doc in docs]
        ids = [doc.doc_id or str(idx) for idx, doc in enumerate(docs)]
        self.vector_store.add_texts(texts=texts, metadatas=metadatas, ids=ids)

    def query(
        self,
        text: str,
        top_k: int = 4,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        return self.vector_store.query(text=text, top_k=top_k, metadata_filter=metadata_filter)
