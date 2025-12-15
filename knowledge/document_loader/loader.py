from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Document:
    content: str
    metadata: Dict[str, object]
    doc_id: Optional[str] = None


def load_document(path: str, metadata: Optional[Dict[str, object]] = None) -> Document:
    """Load a single document (txt or pdf)."""
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    metadata = metadata or {}

    if suffix in {".txt", ""}:
        content = file_path.read_text(encoding="utf-8")
    elif suffix == ".pdf":
        try:
            import pypdf  # type: ignore
        except ImportError as exc:  # pragma: no cover - informative error
            raise RuntimeError("pypdf is required for PDF ingestion") from exc

        reader = pypdf.PdfReader(str(file_path))
        content = "\n".join(page.extract_text() or "" for page in reader.pages)
    else:
        raise ValueError(f"Unsupported document type: {suffix}")

    return Document(content=content, metadata=metadata, doc_id=str(file_path))


def load_documents(paths: List[str]) -> List[Document]:
    return [load_document(path) for path in paths]
