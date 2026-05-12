"""Destructive-action blocklist.

Stops the agent — and any LLM-generated command — from invoking patterns we
consider always-dangerous regardless of scope (mass deletion, fork bombs,
amplification attacks, etc.).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel

from huntersec.exceptions import BlocklistedCommandError


class BlocklistFile(BaseModel):
    """Parsed blocklist configuration."""

    version: int = 1
    # Regex patterns matched against full command string
    forbidden_patterns: list[str]
    # Tokens (executable name) that are never allowed
    forbidden_binaries: list[str]
    # Argument flags that are never allowed (e.g. nmap -sS without rate limit)
    forbidden_flags: list[str] = []


# ── Built-in baseline ───────────────────────────────────────────────────────
# These are baked into the binary even if the YAML file is missing/empty.
# They cannot be turned off via config — only extended.
BAKED_IN_PATTERNS: tuple[str, ...] = (
    r"\brm\s+-rf\s+/(?!\S)",  # rm -rf / (whole root)
    r"\brm\s+-rf\s+~(?:/|\s|$)",  # rm -rf ~
    r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/sd[a-z]",  # disk wipe
    r":\(\)\s*\{\s*:\|\:\&\s*\}\s*;:",  # classic fork bomb
    r"mkfs\.[a-z0-9]+\s+/dev/",  # format disk
    r">\s*/dev/sd[a-z]",  # overwrite block device
    r"chmod\s+-R\s+(?:000|777)\s+/",  # nuke perms on root
    r"\bshred\s+/dev/",
    # DDoS / amplification heuristics
    r"hping3\s.*\s--flood",
    r"slowloris",
    r"\b(?:t50|mhddos|low_orbit|loic|hoic)\b",
    # Mass-mailer / spam
    r"sendmail\s+-bs\s+.*@.*@",
)

BAKED_IN_BINARIES: tuple[str, ...] = (
    "mkfs",
    "shred",
    "fdisk",  # interactive disk partition
    "wipefs",
)


class BlocklistChecker:
    """Check commands against forbidden patterns.

    Designed to be fast (compiled regex) and conservative — false positives are
    acceptable, false negatives are not.
    """

    def __init__(self, extra: BlocklistFile | None = None) -> None:
        patterns = list(BAKED_IN_PATTERNS)
        binaries = set(BAKED_IN_BINARIES)
        flags: set[str] = set()
        if extra:
            patterns.extend(extra.forbidden_patterns)
            binaries.update(extra.forbidden_binaries)
            flags.update(extra.forbidden_flags)
        self._patterns = [re.compile(p) for p in patterns]
        self._binaries = binaries
        self._flags = flags

    @classmethod
    def load(cls, path: Path | None = None) -> Self:
        """Load blocklist from YAML (optional — defaults are baked in)."""
        if path is None or not path.exists():
            return cls(None)
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(BlocklistFile.model_validate(data))

    def check(self, command: str) -> None:
        """Raise :class:`BlocklistedCommandError` if command is forbidden."""
        if not command or not command.strip():
            return
        # Null bytes can be used to bypass string checks — always reject.
        if "\x00" in command:
            raise BlocklistedCommandError(
                f"Command contains null bytes, refusing to run: {command!r}"
            )
        # Pattern match
        for pat in self._patterns:
            if pat.search(command):
                raise BlocklistedCommandError(
                    f"Command matches forbidden pattern {pat.pattern!r}: {command!r}"
                )
        # Token match — truncate to avoid O(n²) behaviour on pathological inputs
        _SHLEX_LIMIT = 4096
        try:
            tokens = shlex.split(command[:_SHLEX_LIMIT])
        except ValueError:
            # Malformed quoting — treat as suspicious
            raise BlocklistedCommandError(
                f"Command has malformed quoting, refusing to run: {command!r}"
            ) from None
        if not tokens:
            return
        binary = Path(tokens[0]).name
        if binary in self._binaries:
            raise BlocklistedCommandError(f"Binary {binary!r} is in the forbidden binaries list.")
        for tok in tokens[1:]:
            if tok in self._flags:
                raise BlocklistedCommandError(f"Flag {tok!r} is in the forbidden flags list.")
