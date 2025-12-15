from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings
from chromadb.utils.embedding_functions import EmbeddingFunction


class SimpleHashEmbeddingFunction(EmbeddingFunction):
    """Deterministic, lightweight embedding for offline/local use."""

    def __call__(self, input: List[str]) -> List[List[float]]:  # type: ignore[override]
        return [self._hash_to_vector(text) for text in input]

    def _hash_to_vector(self, text: str, dim: int = 8) -> List[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        chunk_size = len(digest) // dim
        vector = []
        for i in range(0, len(digest), chunk_size):
            chunk = digest[i : i + chunk_size]
            vector.append(int.from_bytes(chunk, "big") / 1e9)
            if len(vector) == dim:
                break
        return vector


class ChromaVectorStore:
    """Lightweight wrapper around ChromaDB with metadata filtering support."""

    def __init__(
        self,
        collection_name: str = "knowledge_base",
        persist_directory: Optional[str] = None,
        embedding_function: Optional[EmbeddingFunction] = None,
    ) -> None:
        settings = (
            Settings(is_persistent=True, persist_directory=persist_directory)
            if persist_directory
            else Settings()
        )
        self._client = chromadb.Client(settings)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=embedding_function or SimpleHashEmbeddingFunction(),
        )

    def add_texts(
        self,
        texts: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None,
    ) -> None:
        metadatas = metadatas or [{} for _ in texts]
        ids = ids or [str(i) for i in range(len(texts))]
        self._collection.add(documents=texts, metadatas=metadatas, ids=ids)

    def query(
        self,
        text: str,
        top_k: int = 4,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        results = self._collection.query(
            query_texts=[text],
            n_results=top_k,
            where=metadata_filter,
        )
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        ids = results.get("ids", [[]])[0]

        return [
            {"id": doc_id, "content": content, "metadata": metadata}
            for doc_id, content, metadata in zip(ids, documents, metadatas)
        ]
