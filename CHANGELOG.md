# Changelog

All notable changes to HunterSecV1 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 0 — Foundation
- Initial repository scaffolding
- `CLAUDE.md` engineering rules
- `docs/plan.md`, `docs/architecture.md`, `docs/ethics.md`
- Apache 2.0 LICENSE
- pyproject.toml with strict tooling config
- pre-commit hooks (ruff, black, mypy, bandit, detect-secrets, gitleaks)
- GitHub Actions CI skeleton (CI, CodeQL, dependency review)
- Docker Kali sandbox skeleton
- ADR template
- Safety layer: `scope`, `blocklist`, `ratelimit`, `filter`, `audit` modules
- Multi-provider LLM router (`anthropic`, `openai`, `ollama`, `fake`) with token-budget guard and tool-output sanitization
- Docker sandbox executor (ephemeral `--rm` containers, full hardening flags, mock executor for tests)
- CLI skeleton (`hunter run`, `hunter scope`, `hunter version`)

#### Phase 1 — Core Agent
- LangGraph state machine: Planner -> Executor -> Validator -> Reporter nodes with conditional edges
- `AgentState` / `PlanStep` / `ToolOutput` / `Finding` models and `Session` orchestrator
- Tool base + registry; 5 recon tool wrappers (`nmap`, `gobuster`, `ffuf`, `whatweb`, `httpx`)
- Memory layer: SQLite store + semantic/LIKE retriever
- Markdown report generator
- Wired `hunter run` to the live agent loop (dry-run by default, `--execute` to run)

#### Phase 2 — HTB/THM Solver
- Specialized sub-agents: `ReconAgent`, `WebAgent`, `ServiceAgent` (fail-graceful, safety-checked per step)
- 3 additional tool wrappers (`enum4linux-ng`, `searchsploit`, `curl`) - 8 wrappers total
- `HTBSolver` with flag detection, status mapping (solved/partial/failed), 30-min hard cap
- `hunter htb solve` and `hunter thm solve` commands
- Knowledge base: GTFOBins + common-vuln seeds (`configs/knowledge/gtfobins_seed.yaml`)
- `docs/progress_report.md`, `docs/htb-windows.md`

### Changed
- `BaseTool.run` now raises `ToolError` on exit code 127 (missing binary) instead of returning empty output
- `ReconSummary` caches directories / `gobuster_ran` so `WebAgent` reuses results instead of re-scanning

### Fixed
- E2E (HTB "Three") fixes: missing recon tools added to Kali image; host-network mode for HTB VPN; exit-127 audit handling; synthetic-web-port logic; double-scan dedupe; UTF-8 console wrapping on Windows

### Security
- Default-deny scope guard design
- Destructive-action blocklist design
- JSONL hash-chained audit log design

### Tests
- 210 unit tests passing; ruff clean

## [0.1.0] - TBD

Initial public release (Phase 0 complete).

[Unreleased]: https://github.com/plastma65/HunterSecV1/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/plastma65/HunterSecV1/releases/tag/v0.1.0
