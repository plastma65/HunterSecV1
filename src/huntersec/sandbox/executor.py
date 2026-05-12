"""Sandbox executor — runs commands inside a hardened Docker container.

Every tool invocation in HunterSecV1 goes through :class:`SandboxExecutor`.
The executor constructs a ``docker run`` command from a strict argument list
(no ``shell=True``) and applies all hardening flags from
:class:`~huntersec.settings.SandboxSettings`.

Security invariants:
* The ``docker`` binary is invoked via :func:`asyncio.create_subprocess_exec`
  — never via a shell.
* The command passed by the caller is tokenized with :func:`shlex.split` and
  injected as individual argv tokens — no string concatenation.
* Every execution is logged through :class:`~huntersec.safety.audit.AuditLogger`.
"""

# This module handles offensive primitive: subprocess execution inside Docker.
# Safety: commands are tokenized with shlex.split, no shell=True anywhere,
# all container hardening flags from SandboxSettings are applied.

from __future__ import annotations

import asyncio
import shlex
import time
from typing import TypedDict

import structlog

from huntersec.exceptions import SandboxError, SandboxTimeoutError
from huntersec.safety.audit import AuditLogger
from huntersec.settings import SandboxSettings

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ExecutionResult(TypedDict):
    """Result of a sandboxed command execution.

    Attributes:
        stdout: Standard output captured from the container.
        stderr: Standard error captured from the container.
        exit_code: Container process exit code (0 = success).
        duration_ms: Wall-clock execution time in milliseconds.
    """

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int


class SandboxExecutor:
    """Execute commands inside a hardened Docker container.

    Args:
        settings: Sandbox configuration (image, resource limits, etc.).
        audit: Audit logger; every execution is recorded before and after.

    Example:
        >>> import asyncio
        >>> from huntersec.settings import SandboxSettings
        >>> from huntersec.safety.audit import AuditLogger
        >>> from pathlib import Path
        >>> audit = AuditLogger(Path("data/audit"))
        >>> executor = SandboxExecutor(SandboxSettings(), audit)
        >>> result = asyncio.run(executor.run("nmap --version"))
    """

    def __init__(self, settings: SandboxSettings, audit: AuditLogger) -> None:
        self._settings = settings
        self._audit = audit

    def _build_docker_argv(self, command_tokens: list[str]) -> list[str]:
        """Construct the full ``docker run`` argument list.

        Args:
            command_tokens: Pre-tokenized command to run inside the container.

        Returns:
            Complete argv list suitable for :func:`asyncio.create_subprocess_exec`.
        """
        s = self._settings
        return [
            "docker",
            "run",
            "--rm",
            "--runtime",
            s.runtime,
            "--network",
            s.network_mode,
            "--memory",
            s.memory_limit,
            "--cpus",
            str(s.cpu_limit),
            "--pids-limit",
            str(s.pids_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:noexec,nosuid,size=256m",
            "--user",
            "huntersec",
            s.image,
            *command_tokens,
        ]

    async def run(
        self,
        command: str,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Run a command inside the Docker sandbox.

        Args:
            command: Shell command string (e.g. ``"nmap -sV 192.0.2.1"``).
                Tokenized with :func:`shlex.split`; pipelines are not supported
                (no shell inside the container).
            timeout: Per-execution timeout in seconds.  Defaults to
                ``SandboxSettings.default_timeout_seconds``.

        Returns:
            :class:`ExecutionResult` with stdout, stderr, exit_code,
            duration_ms.

        Raises:
            SandboxTimeoutError: If the command exceeds the timeout.
            SandboxError: If Docker is unavailable or the process cannot start.
        """
        effective_timeout = timeout or self._settings.default_timeout_seconds

        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise SandboxError(
                f"Command has malformed quoting, refusing to run: {command!r}"
            ) from exc

        if not tokens:
            raise SandboxError("Empty command string passed to SandboxExecutor.")

        docker_argv = self._build_docker_argv(tokens)

        self._audit.log_event(
            "sandbox.exec.start",
            {"command": command, "timeout": effective_timeout, "image": self._settings.image},
        )
        log.info("sandbox.exec.start", command=command, timeout=effective_timeout)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603,S607
                *docker_argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(effective_timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()  # drain pipes to prevent zombie
                raise SandboxTimeoutError(
                    f"Command timed out after {effective_timeout}s: {command!r}"
                )
        except (SandboxError, SandboxTimeoutError):
            raise
        except Exception as exc:
            raise SandboxError(f"Failed to start Docker sandbox: {exc}") from exc
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)

        exit_code = proc.returncode if proc.returncode is not None else -1
        result: ExecutionResult = {
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace"),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        }

        self._audit.log_event(
            "sandbox.exec.end",
            {
                "command": command,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "stdout_bytes": len(stdout_bytes),
                "stderr_bytes": len(stderr_bytes),
            },
        )
        log.info(
            "sandbox.exec.end",
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

        return result
