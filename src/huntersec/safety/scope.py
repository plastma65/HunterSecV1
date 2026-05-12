"""Scope validator.

Parses ``configs/scope.yaml`` and decides whether a target (IP, CIDR, hostname,
URL) is authorized for testing.

Default behaviour is **fail-closed**: missing scope file ⇒
:class:`ScopeNotConfiguredError`.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Self
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, field_validator

from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError


class ScopeFile(BaseModel):
    """Parsed representation of a scope.yaml file."""

    version: int = 1
    name: str = "default"
    program: str | None = None  # e.g. "HackTheBox", "HackerOne XYZ Co."
    networks: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("networks")
    @classmethod
    def _validate_networks(cls, v: list[str]) -> list[str]:
        for net in v:
            ipaddress.ip_network(net, strict=False)  # raises if invalid
        return v


class ScopeValidator:
    """Validate targets against the active scope.

    Example:
        >>> v = ScopeValidator.load(Path("configs/scope.yaml"))
        >>> v.assert_in_scope("10.10.11.42")
    """

    def __init__(self, scope: ScopeFile) -> None:
        self._scope = scope
        self._networks = [ipaddress.ip_network(n, strict=False) for n in scope.networks]

    @classmethod
    def load(cls, path: Path) -> Self:
        """Load and validate a scope file.

        Raises:
            ScopeNotConfiguredError: if file missing.
            pydantic.ValidationError: if file malformed.
        """
        if not path.exists():
            raise ScopeNotConfiguredError(
                f"Scope file not found at {path}. Refusing to proceed. "
                "Copy configs/scope.example.yaml and define your authorized scope."
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(ScopeFile.model_validate(data))

    def is_in_scope(self, target: str) -> bool:
        """Return True if target is authorized. Never raises for ergonomic checks."""
        try:
            self.assert_in_scope(target)
        except OutOfScopeError:
            return False
        return True

    def assert_in_scope(self, target: str) -> None:
        """Raise :class:`OutOfScopeError` if target is not authorized."""
        # 1. Normalize target
        host = self._extract_host(target)

        # 2. Explicit deny wins
        if host in self._scope.out_of_scope:
            raise OutOfScopeError(f"Target {host!r} is explicitly out-of-scope.")

        # 3. IP / CIDR match
        try:
            addr = ipaddress.ip_address(host)
            for net in self._networks:
                if addr in net:
                    return
        except ValueError:
            pass

        # 4. Hostname / domain match
        for h in self._scope.hostnames:
            if host == h or host.endswith("." + h.lstrip(".")):
                return

        # 5. URL match
        for u in self._scope.urls:
            if target.startswith(u):
                return

        raise OutOfScopeError(
            f"Target {host!r} (raw: {target!r}) is not in active scope {self._scope.name!r}."
        )

    @staticmethod
    def _extract_host(target: str) -> str:
        """Pull a comparable host token from URL/IP/host:port/CIDR."""
        if "://" in target:
            return urlparse(target).hostname or target
        if "/" in target:  # CIDR like 10.0.0.0/24
            return target.split("/", 1)[0]
        if ":" in target and not target.count(":") > 1:  # host:port (not IPv6)
            return target.split(":", 1)[0]
        return target
