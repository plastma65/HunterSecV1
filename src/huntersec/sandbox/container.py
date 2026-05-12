"""Managed Docker container lifecycle.

:class:`ManagedContainer` starts and stops a long-lived container so that
multiple :class:`~huntersec.sandbox.executor.SandboxExecutor` calls can share
the same container session without the cold-start overhead of ``docker run``
per command.

This is optional — the default :class:`~huntersec.sandbox.executor.SandboxExecutor`
uses ephemeral containers (``--rm``).  Use :class:`ManagedContainer` when you
need a persistent working directory or installed state between commands.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from huntersec.exceptions import SandboxError, SandboxStartupError
from huntersec.settings import SandboxSettings

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ManagedContainer:
    """Async context manager for a persistent Docker container.

    Args:
        settings: Sandbox configuration used to apply hardening flags.
        name: Optional container name.  Auto-generated if omitted.

    Example:
        >>> import asyncio
        >>> from huntersec.settings import SandboxSettings
        >>> async def demo():
        ...     async with ManagedContainer(SandboxSettings()) as ctr:
        ...         print(f"Container ID: {ctr.container_id}")
        >>> asyncio.run(demo())
    """

    def __init__(
        self,
        settings: SandboxSettings,
        name: str | None = None,
    ) -> None:
        self._settings = settings
        self._name = name
        self._container_id: str | None = None

    @property
    def container_id(self) -> str | None:
        """Docker container ID; ``None`` before :meth:`start` is called."""
        return self._container_id

    def _build_start_argv(self) -> list[str]:
        """Build ``docker run -d`` argument list for a background container.

        Returns:
            Argument list for :func:`asyncio.create_subprocess_exec`.
        """
        s = self._settings
        argv = [
            "docker",
            "run",
            "-d",
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
            "/tmp:noexec,nosuid,size=256m",  # noqa: S108  # nosec B108
            "--user",
            "huntersec",
        ]
        if self._name:
            argv += ["--name", self._name]
        # Keep container alive waiting for exec commands
        argv += [s.image, "sleep", "infinity"]
        return argv

    async def start(self) -> str:
        """Start the container in the background.

        Returns:
            The full container ID string.

        Raises:
            SandboxStartupError: If ``docker run -d`` fails.
        """
        argv = self._build_start_argv()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except Exception as exc:
            raise SandboxStartupError(f"Failed to start container: {exc}") from exc

        if proc.returncode != 0:
            raise SandboxStartupError(
                f"docker run -d failed (exit {proc.returncode}): "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )

        cid = stdout.decode("utf-8").strip()
        self._container_id = cid
        log.info("sandbox.container.started", container_id=cid[:12])
        return cid

    async def stop(self) -> None:
        """Stop and remove the running container.

        Raises:
            SandboxError: If ``docker rm -f`` fails unexpectedly.
        """
        if self._container_id is None:
            return
        cid = self._container_id
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                cid,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
        except Exception as exc:
            raise SandboxError(f"Failed to stop container {cid[:12]}: {exc}") from exc

        if proc.returncode != 0:
            log.warning(
                "sandbox.container.stop_failed",
                container_id=cid[:12],
                stderr=stderr.decode("utf-8", errors="replace").strip(),
            )
        else:
            log.info("sandbox.container.stopped", container_id=cid[:12])
        self._container_id = None

    async def __aenter__(self) -> ManagedContainer:
        """Start container and return self."""
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        """Stop and clean up the container on context exit."""
        await self.stop()
