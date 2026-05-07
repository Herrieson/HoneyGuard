from __future__ import annotations

import shlex
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional
import os
import subprocess
import logging
import sys

from python_on_whales import DockerClient, docker
from python_on_whales.exceptions import DockerException


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


class SandboxManager:
    """Manage per-session sandbox containers backed by Docker."""

    LOCAL_PATH_PREFIXES = ("srv", "tmp", "secrets", "home", "var", "opt", "etc")
    LOCAL_SPECIAL_PREFIXES = ("/usr/local/bin",)
    LOCAL_ALLOWED_HOST_PATHS = ("/dev/null", "/bin/bash", "/bin/sh", "/usr/bin/env")

    def __init__(
        self,
        image_tag: str = "hse-sandbox:latest",
        base_image: str = "python:3.10-slim",
        network_mode: str | None = None,
        cpus: float | None = None,
        memory: str | None = None,
    ) -> None:
        self.log = logging.getLogger(__name__)
        self.backend = os.getenv("HSE_SANDBOX_BACKEND", "docker").strip().lower() or "docker"
        if self.backend in {"host", "local"}:
            self.backend = "local"
        elif self.backend not in {"docker"}:
            raise ValueError("HSE_SANDBOX_BACKEND must be either 'docker' or 'local'")
        self.image_tag = image_tag
        self.base_image = base_image
        # Default to no network unless explicitly allowed via env or argument.
        env_network = os.getenv("HSE_SANDBOX_NETWORK")
        self.network_mode = network_mode if network_mode is not None else (env_network if env_network is not None else "none")
        # Optional container-level resource limits
        env_cpus = os.getenv("HSE_SANDBOX_CPUS")
        self.cpus = cpus if cpus is not None else (float(env_cpus) if env_cpus else None)
        self.memory = memory if memory is not None else os.getenv("HSE_SANDBOX_MEMORY")
        self._containers: Dict[str, str] = {}
        self._session_roots: Dict[str, Path] = {}
        self.local_root = Path(os.getenv("HSE_LOCAL_SANDBOX_ROOT", "/tmp/hse-local-sandboxes")).resolve()
        self.keep_local_sessions = os.getenv("HSE_LOCAL_SANDBOX_KEEP", "false").lower() in {"1", "true", "yes"}
        self._docker: DockerClient = docker
        self.project_root = Path(__file__).resolve().parents[2]
        self.dockerfile_path = self.project_root / "environment" / "sandbox" / "Dockerfile"

    def start(self, session_id: str) -> str:
        """Start a fresh sandbox container for the session."""
        if self.backend == "local":
            return self._start_local(session_id)

        self._ensure_image()
        if session_id in self._containers:
            self._remove_container(self._containers[session_id])
            del self._containers[session_id]

        labels = {"hse": "true", "session_id": session_id}
        run_kwargs = {}
        if self.network_mode:
            run_kwargs["networks"] = [self.network_mode]
        if self.cpus:
            run_kwargs["cpus"] = self.cpus
        if self.memory:
            run_kwargs["memory"] = self.memory
        container = self._docker.container.run(
            self.image_tag,
            name=f"hse-{session_id}",
            detach=True,
            tty=True,
            command=["sleep", "infinity"],
            labels=labels,
            **run_kwargs,
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
        if self.backend == "local":
            return self._execute_local(session_id, cmd, workdir=workdir, env=env, timeout_sec=timeout_sec)

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
        if self.backend == "local":
            self._mount_file_local(session_id, path, content)
            return

        container_id = self._get_container(session_id)
        target_path = Path(path)

        # Skip virtual or protected filesystems where writes are not allowed.
        if target_path.is_absolute() and len(target_path.parts) > 1 and target_path.parts[1] in {"proc", "sys", "dev"}:
            self.log.warning("Skipping mount of %s into container %s (virtual filesystem)", path, container_id)
            return

        directory = str(target_path.parent)
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
        if self.backend == "local":
            self.shutdown(session_id)
            return self.start(session_id)

        if session_id in self._containers:
            self._remove_container(self._containers[session_id])
            del self._containers[session_id]
        return self.start(session_id)

    def shutdown(self, session_id: str) -> None:
        """Stop and remove the sandbox container for a session."""
        if self.backend == "local":
            root = self._session_roots.pop(session_id, None)
            if root and root.exists() and not self.keep_local_sessions:
                shutil.rmtree(root, ignore_errors=True)
            return

        container_id = self._containers.get(session_id)
        if container_id:
            self._remove_container(container_id)
            del self._containers[session_id]

    def cleanup_all(self) -> None:
        """Remove all containers labeled as HSE sandboxes."""
        if self.backend == "local":
            active_roots = {root.resolve() for root in self._session_roots.values()}
            if not self.local_root.exists() or self.keep_local_sessions:
                return
            for candidate in self.local_root.glob("*"):
                try:
                    resolved = candidate.resolve()
                except OSError:
                    continue
                if resolved in active_roots:
                    continue
                if candidate.is_dir():
                    shutil.rmtree(candidate, ignore_errors=True)
            return

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

    def _start_local(self, session_id: str) -> str:
        if session_id in self._session_roots:
            self.shutdown(session_id)
        root = (self.local_root / session_id).resolve()
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True, exist_ok=True)
        for name in (*self.LOCAL_PATH_PREFIXES, "usr/local/bin"):
            (root / name).mkdir(parents=True, exist_ok=True)
        shim_dir = root / ".hse" / "bin"
        shim_dir.mkdir(parents=True, exist_ok=True)
        for name in ("python", "python3"):
            target = shim_dir / name
            if target.exists() or target.is_symlink():
                target.unlink()
            try:
                target.symlink_to(sys.executable)
            except OSError:
                shutil.copy2(sys.executable, target)
        self._session_roots[session_id] = root
        return f"local:{root}"

    def _execute_local(
        self,
        session_id: str,
        cmd: str,
        workdir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_sec: Optional[int] = None,
    ) -> CommandResult:
        root = self._get_local_root(session_id)
        denied_path = self._unsupported_local_absolute_path(cmd)
        if denied_path:
            return CommandResult(
                stdout="",
                stderr=f"[local_sandbox] denied unsupported absolute path outside virtual roots: {denied_path}",
                exit_code=126,
            )
        full_cmd = self._rewrite_local_paths(session_id, cmd)
        if self._looks_like_local_root_destruction(full_cmd):
            return CommandResult(
                stdout="",
                stderr="[local_sandbox] denied command that targets the container root",
                exit_code=126,
            )
        cwd = self._local_host_path(session_id, workdir).resolve() if workdir else root
        cwd.mkdir(parents=True, exist_ok=True)
        run_env = os.environ.copy()
        run_env.update(env or {})
        run_env["HSE_SANDBOX_BACKEND"] = "local"
        run_env["HSE_SANDBOX_ROOT"] = str(root)
        run_env.setdefault("HOME", str(root / "home" / "app"))
        run_env["PATH"] = f"{root / '.hse' / 'bin'}:{run_env.get('PATH', '')}"
        try:
            completed = subprocess.run(
                ["bash", "-lc", full_cmd],
                cwd=str(cwd),
                env=run_env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            return CommandResult(
                stdout=self._unrewrite_local_paths(session_id, completed.stdout),
                stderr=self._unrewrite_local_paths(session_id, completed.stderr),
                exit_code=completed.returncode,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            if stderr:
                stderr = f"{stderr}\n[local_sandbox] command timed out after {timeout_sec}s"
            else:
                stderr = f"[local_sandbox] command timed out after {timeout_sec}s"
            return CommandResult(
                stdout=self._unrewrite_local_paths(session_id, stdout),
                stderr=self._unrewrite_local_paths(session_id, stderr),
                exit_code=124,
            )

    def _mount_file_local(self, session_id: str, path: str, content: str) -> None:
        target_path = Path(path)
        if target_path.is_absolute() and len(target_path.parts) > 1 and target_path.parts[1] in {"proc", "sys", "dev"}:
            self.log.warning("Skipping local mount of %s (virtual filesystem)", path)
            return
        host_path = self._local_host_path(session_id, path)
        host_path.parent.mkdir(parents=True, exist_ok=True)
        text = content
        if self._should_rewrite_local_file_content(path, text):
            text = self._rewrite_local_paths(session_id, text)
        host_path.write_text(text, encoding="utf-8")
        if str(path).startswith("/usr/local/bin/") or str(path).endswith(".sh"):
            try:
                host_path.chmod(0o755)
            except OSError:
                pass

    def _get_local_root(self, session_id: str) -> Path:
        root = self._session_roots.get(session_id)
        if not root:
            raise ValueError(f"No active local sandbox for session {session_id}")
        return root

    def _local_host_path(self, session_id: str, virtual_path: Optional[str]) -> Path:
        root = self._get_local_root(session_id)
        if not virtual_path:
            return root
        raw = Path(str(virtual_path))
        if raw.is_absolute():
            mapped = root / str(raw).lstrip("/")
        else:
            mapped = root / raw
        resolved = mapped.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Path escapes local sandbox root: {virtual_path}") from exc
        return resolved

    def _rewrite_local_paths(self, session_id: str, text: str) -> str:
        root = self._get_local_root(session_id)
        protected = f"__HSE_LOCAL_ROOT_{session_id}__"
        rewritten = str(text).replace(str(root), protected)

        replacements: list[tuple[str, str]] = []
        for prefix in self.LOCAL_SPECIAL_PREFIXES:
            replacements.append((prefix, str(root / prefix.lstrip("/"))))
        for name in self.LOCAL_PATH_PREFIXES:
            replacements.append((f"/{name}", str(root / name)))

        placeholders: list[tuple[str, str]] = []
        for idx, (virtual, host) in enumerate(sorted(replacements, key=lambda item: len(item[0]), reverse=True)):
            placeholder = f"__HSE_LOCAL_PATH_{session_id}_{idx}__"
            pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(virtual)}(?=$|[/\s'\";:,\)\]\}}])")
            rewritten = pattern.sub(placeholder, rewritten)
            placeholders.append((placeholder, host))
        for placeholder, host in placeholders:
            rewritten = rewritten.replace(placeholder, host)
        return rewritten.replace(protected, str(root))

    def _unrewrite_local_paths(self, session_id: str, text: str) -> str:
        if not text:
            return text
        root = self._get_local_root(session_id)
        rewritten = str(text)
        replacements: list[tuple[str, str]] = []
        for prefix in self.LOCAL_SPECIAL_PREFIXES:
            replacements.append((str(root / prefix.lstrip("/")), prefix))
        for name in self.LOCAL_PATH_PREFIXES:
            replacements.append((str(root / name), f"/{name}"))
        replacements.append((str(root) + "/", "/"))
        replacements.append((str(root), "/"))
        for host, virtual in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
            rewritten = rewritten.replace(host, virtual)
        return rewritten

    def _should_rewrite_local_file_content(self, path: str, content: str) -> bool:
        target = str(path)
        if target.startswith("/usr/local/bin/"):
            return True
        suffix = Path(target).suffix
        if suffix in {".py", ".sh"}:
            return True
        first_line = content.splitlines()[0] if content.splitlines() else ""
        return first_line.startswith("#!") and any(shell in first_line for shell in ("bash", "sh", "python"))

    def _unsupported_local_absolute_path(self, cmd: str) -> Optional[str]:
        allowed_prefixes = {f"/{name}" for name in self.LOCAL_PATH_PREFIXES}
        for prefix in self.LOCAL_SPECIAL_PREFIXES:
            allowed_prefixes.add(prefix)
        allowed_exact = set(self.LOCAL_ALLOWED_HOST_PATHS)
        if re.search(r"(?<![A-Za-z0-9_.:-])/(?:\s|$|[;&|)\*])", str(cmd)):
            return "/"
        pattern = re.compile(r"(?<![A-Za-z0-9_.:-])/(?!/)([A-Za-z][A-Za-z0-9_.-]*)([^\s'\";|&<>)]*)?")
        for match in pattern.finditer(str(cmd)):
            path = "/" + match.group(1) + (match.group(2) or "")
            if path in allowed_exact:
                continue
            if path.startswith("/dev/"):
                if path == "/dev/null":
                    continue
                return path
            if any(path == prefix or path.startswith(prefix + "/") for prefix in allowed_prefixes):
                continue
            return path
        return None

    def _looks_like_local_root_destruction(self, cmd: str) -> bool:
        destructive_rm = re.search(r"\brm\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*r[A-Za-z]*\s+/(?:\s|$|\*)", cmd)
        if destructive_rm:
            return True
        return bool(re.search(r"\b(?:shutdown|reboot|halt|poweroff)\b", cmd))

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
