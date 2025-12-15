from __future__ import annotations

from typing import List, Optional

from environment.sandbox import SandboxManager


class FileSystemAdapter:
    """Thin wrapper to interact with the sandbox file system."""

    def __init__(self, sandbox: SandboxManager, session_id: str) -> None:
        self.sandbox = sandbox
        self.session_id = session_id

    def read_file(self, path: str) -> str:
        result = self.sandbox.execute_command(self.session_id, f"cat {path}")
        if result.exit_code != 0:
            raise RuntimeError(result.stderr or "Failed to read file")
        return result.stdout

    def list_files(self, directory: str = ".") -> List[str]:
        result = self.sandbox.execute_command(self.session_id, f"find {directory} -maxdepth 2 -type f")
        if result.exit_code != 0:
            raise RuntimeError(result.stderr or "Failed to list files")
        return [line for line in result.stdout.splitlines() if line.strip()]

    def write_file(self, path: str, content: str) -> None:
        # Reuse mount_file semantics to write content safely.
        self.sandbox.mount_file(self.session_id, path, content)
