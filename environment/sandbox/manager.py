from __future__ import annotations

import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional
import os
import subprocess

from python_on_whales import DockerClient, docker
from python_on_whales.exceptions import DockerException


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


class SandboxManager:
    """Manage per-session sandbox containers backed by Docker."""

    def __init__(
        self,
        image_tag: str = "hse-sandbox:latest",
        base_image: str = "python:3.10-slim",
    ) -> None:
        self.image_tag = image_tag
        self.base_image = base_image
        self._containers: Dict[str, str] = {}
        self._docker: DockerClient = docker
        self.project_root = Path(__file__).resolve().parents[2]
        self.dockerfile_path = self.project_root / "environment" / "sandbox" / "Dockerfile"

    def start(self, session_id: str) -> str:
        """Start a fresh sandbox container for the session."""
        self._ensure_image()
        if session_id in self._containers:
            self._remove_container(self._containers[session_id])
            del self._containers[session_id]

        labels = {"hse": "true", "session_id": session_id}
        container = self._docker.container.run(
            self.image_tag,
            name=f"hse-{session_id}",
            detach=True,
            tty=True,
            command=["sleep", "infinity"],
            labels=labels,
        )
        self._containers[session_id] = container.id
        return container.id

    def execute_command(
        self,
        session_id: str,
        cmd: str,
        workdir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_sec: Optional[int] = None,
        cpu_limit: Optional[str] = None,
        mem_limit: Optional[str] = None,
    ) -> CommandResult:
        container_id = self._get_container(session_id)
        full_cmd = cmd
        if timeout_sec:
            full_cmd = f"timeout {int(timeout_sec)}s {cmd}"
        try:
            # python-on-whales container.execute does not accept cpu/memory limits; set those at container start if needed
            exec_kwargs = {
                "workdir": workdir,
                "envs": env or {},
            }
            output = self._docker.container.execute(
                container_id,
                ["bash", "-lc", full_cmd],
                **{k: v for k, v in exec_kwargs.items() if v},
            )
            stdout = output if isinstance(output, str) else "".join(
                chunk.decode() if isinstance(chunk, bytes) else str(chunk) for _, chunk in output  # type: ignore[arg-type]
            ) if output else ""
            return CommandResult(stdout=stdout, stderr="", exit_code=0)
        except DockerException as exc:
            stdout = getattr(exc, "stdout", "") or ""
            stderr = getattr(exc, "stderr", "") or str(exc)
            exit_code = getattr(exc, "return_code", 1)
            return CommandResult(
                stdout.decode() if hasattr(stdout, "decode") else stdout,
                stderr.decode() if hasattr(stderr, "decode") else stderr,
                exit_code,
            )

    def mount_file(self, session_id: str, path: str, content: str) -> None:
        """Copy a file into the sandbox container."""
        container_id = self._get_container(session_id)
        directory = str(Path(path).parent)
        self.execute_command(session_id, f"mkdir -p {shlex.quote(directory)}")

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
                tmp.write(content)
                tmp.flush()
                tmp_path = tmp.name
            self._docker.copy(tmp_path, (container_id, path))
        finally:
            if tmp_path and Path(tmp_path).exists():
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def reset(self, session_id: str) -> str:
        """Tear down and recreate the sandbox for a session."""
        if session_id in self._containers:
            self._remove_container(self._containers[session_id])
            del self._containers[session_id]
        return self.start(session_id)

    def shutdown(self, session_id: str) -> None:
        """Stop and remove the sandbox container for a session."""
        container_id = self._containers.get(session_id)
        if container_id:
            self._remove_container(container_id)
            del self._containers[session_id]

    def cleanup_all(self) -> None:
        """Remove all containers labeled as HSE sandboxes."""
        try:
            containers = self._docker.container.list(filters={"label": "hse=true"})
            active_ids = set(self._containers.values())
            for c in containers:
                # skip containers we still track as active sessions
                if c.id in active_ids:
                    continue
                self._remove_container(c.id)
        except DockerException:
            pass

    def _remove_container(self, container_id: str) -> None:
        try:
            self._docker.container.stop(container_id)
        except DockerException:
            pass
        remover = getattr(self._docker.container, "remove", None) or getattr(
            self._docker.container, "rm", None
        )
        if remover is not None:
            try:
                remover(container_id, force=True)
            except DockerException:
                pass

    def _ensure_image(self) -> None:
        if not self._image_exists():
            self._docker.build(
                context_path=str(self.project_root),
                file=str(self.dockerfile_path),
                tags=self.image_tag,
                build_args={"BASE_IMAGE": self.base_image},
            )

    def _image_exists(self) -> bool:
        try:
            self._docker.image.inspect(self.image_tag)
            return True
        except DockerException:
            return False

    def _get_container(self, session_id: str) -> str:
        container_id = self._containers.get(session_id)
        if not container_id:
            raise ValueError(f"No active sandbox for session {session_id}")
        return container_id
