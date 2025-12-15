from __future__ import annotations

from typing import Dict, Optional


class MockNetworkClient:
    """Mockable network layer to simulate API responses without real outbound calls."""

    def __init__(self, fixtures: Optional[Dict[str, str]] = None) -> None:
        self.fixtures = fixtures or {}

    def get(self, url: str) -> str:
        if url in self.fixtures:
            return self.fixtures[url]
        raise RuntimeError(f"Mock response not found for {url}")

    def register(self, url: str, response: str) -> None:
        self.fixtures[url] = response
