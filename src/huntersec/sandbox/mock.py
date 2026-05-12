"""Mock sandbox executor for unit tests.

:class:`MockSandboxExecutor` replaces :class:`~huntersec.sandbox.executor.SandboxExecutor`
in tests, returning scripted :class:`~huntersec.sandbox.executor.ExecutionResult`
objects without touching Docker.

It records every call so tests can assert on the commands received.
"""

from __future__ import annotations

from huntersec.sandbox.executor import ExecutionResult

_DEFAULT_RESULT: ExecutionResult = {
    "stdout": "mock output",
    "stderr": "",
    "exit_code": 0,
    "duration_ms": 1,
}


class MockSandboxExecutor:
    """Deterministic mock that replaces :class:`~huntersec.sandbox.executor.SandboxExecutor`.

    Args:
        scripted_results: Responses returned in order on successive ``run`` calls.
            When the list is exhausted, ``default_result`` is returned.
        default_result: Fallback result used after scripted list runs out.

    Example:
        >>> from huntersec.sandbox.mock import MockSandboxExecutor
        >>> mock = MockSandboxExecutor()
        >>> import asyncio
        >>> result = asyncio.run(mock.run("nmap -sV 192.0.2.1"))
        >>> result["exit_code"]
        0
        >>> mock.call_history
        ['nmap -sV 192.0.2.1']
    """

    def __init__(
        self,
        scripted_results: list[ExecutionResult] | None = None,
        default_result: ExecutionResult | None = None,
    ) -> None:
        self._scripted = list(scripted_results or [])
        self._default = default_result or _DEFAULT_RESULT
        self.call_history: list[str] = []

    async def run(
        self,
        command: str,
        timeout: int | None = None,  # noqa: ARG002
    ) -> ExecutionResult:
        """Return the next scripted result (or default).

        Args:
            command: Command string (recorded in :attr:`call_history`).
            timeout: Ignored by the mock.

        Returns:
            Next scripted :class:`~huntersec.sandbox.executor.ExecutionResult`
            or :attr:`_default` if the list is exhausted.
        """
        self.call_history.append(command)
        if self._scripted:
            return self._scripted.pop(0)
        return self._default
