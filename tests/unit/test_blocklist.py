"""Unit tests for huntersec.safety.blocklist.BlocklistChecker."""

from __future__ import annotations

from pathlib import Path

import pytest

from huntersec.exceptions import BlocklistedCommandError
from huntersec.safety.blocklist import BlocklistChecker, BlocklistFile


# ── Allowed commands (should not raise) ───────────────────────────────────────


def test_blocklist_checker_allows_nmap_scan() -> None:
    checker = BlocklistChecker()
    checker.check("nmap -sV 192.0.2.1")


def test_blocklist_checker_allows_curl_request() -> None:
    checker = BlocklistChecker()
    checker.check("curl -s http://192.0.2.1/")


def test_blocklist_checker_allows_echo() -> None:
    checker = BlocklistChecker()
    checker.check("echo hello")


def test_blocklist_checker_allows_empty_command() -> None:
    checker = BlocklistChecker()
    checker.check("")  # should not raise


def test_blocklist_checker_allows_whitespace_command() -> None:
    checker = BlocklistChecker()
    checker.check("   ")  # should not raise


# ── Forbidden patterns ────────────────────────────────────────────────────────


def test_blocklist_checker_blocks_rm_rf_root() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError, match="forbidden pattern"):
        checker.check("rm -rf /")


def test_blocklist_checker_blocks_rm_rf_tilde() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("rm -rf ~/")


def test_blocklist_checker_blocks_fork_bomb() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check(":(){:|:&};:")


def test_blocklist_checker_blocks_disk_wipe_dd() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("dd if=/dev/zero of=/dev/sda")


def test_blocklist_checker_blocks_disk_wipe_dd_urandom() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("dd if=/dev/urandom of=/dev/sdb")


def test_blocklist_checker_blocks_mkfs() -> None:
    checker = BlocklistChecker()
    # mkfs.ext4 is caught by the regex pattern (mkfs\.[a-z0-9]+\s+/dev/)
    # before the binary-name check, so match on "forbidden" covers both paths.
    with pytest.raises(BlocklistedCommandError, match="forbidden"):
        checker.check("mkfs.ext4 /dev/sda1")


def test_blocklist_checker_blocks_shred() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("shred /dev/sda")


def test_blocklist_checker_blocks_chmod_777_root() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("chmod -R 777 /")


def test_blocklist_checker_blocks_hping3_flood() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("hping3 192.0.2.1 --flood -S")


def test_blocklist_checker_blocks_loic() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("/opt/loic --target 192.0.2.1")


# ── Forbidden binaries ────────────────────────────────────────────────────────


def test_blocklist_checker_blocks_wipefs_binary() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("wipefs -a /dev/sda")


def test_blocklist_checker_blocks_fdisk_binary() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError):
        checker.check("fdisk /dev/sda")


# ── Malformed quoting ─────────────────────────────────────────────────────────


def test_blocklist_checker_rejects_malformed_quoting() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError, match="malformed quoting"):
        checker.check("echo 'unterminated")


def test_blocklist_checker_rejects_unmatched_double_quote() -> None:
    checker = BlocklistChecker()
    with pytest.raises(BlocklistedCommandError, match="malformed quoting"):
        checker.check('nmap "missing-close')


# ── Extra patterns via YAML ───────────────────────────────────────────────────


def test_blocklist_checker_loads_extra_patterns_from_yaml(tmp_path: Path) -> None:
    yaml_content = (
        "version: 1\n"
        "forbidden_patterns:\n"
        "  - '\\bcustom_evil_tool\\b'\n"
        "forbidden_binaries:\n"
        "  - custom_evil_tool\n"
        "forbidden_flags: []\n"
    )
    blocklist_file = tmp_path / "blocklist.yaml"
    blocklist_file.write_text(yaml_content, encoding="utf-8")

    checker = BlocklistChecker.load(blocklist_file)
    with pytest.raises(BlocklistedCommandError):
        checker.check("custom_evil_tool --run")


def test_blocklist_checker_load_with_no_file_uses_defaults() -> None:
    checker = BlocklistChecker.load(None)
    # Baked-in rules should still apply
    with pytest.raises(BlocklistedCommandError):
        checker.check("rm -rf /")


def test_blocklist_checker_load_with_missing_file_uses_defaults(tmp_path: Path) -> None:
    checker = BlocklistChecker.load(tmp_path / "nonexistent.yaml")
    with pytest.raises(BlocklistedCommandError):
        checker.check("rm -rf /")


# ── Adversarial inputs ────────────────────────────────────────────────────────


def test_blocklist_checker_with_null_bytes_in_command() -> None:
    checker = BlocklistChecker()
    # Null bytes are rejected explicitly in BlocklistChecker.check()
    # (shlex behaviour varies across platforms, so we guard it ourselves).
    with pytest.raises(BlocklistedCommandError, match="null"):
        checker.check("echo\x00payload")


def test_blocklist_checker_with_long_command_does_not_hang() -> None:
    checker = BlocklistChecker()
    # 10 MB command — should complete quickly
    big_cmd = "echo " + "A" * (10 * 1024 * 1024)
    # Should either pass or raise BlocklistedCommandError, not hang
    try:
        checker.check(big_cmd)
    except (BlocklistedCommandError, MemoryError):
        pass
