# Changelog

All notable changes to HunterSecV1 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository scaffolding
- `CLAUDE.md` engineering rules
- `docs/plan.md`, `docs/architecture.md`, `docs/ethics.md`
- Apache 2.0 LICENSE
- pyproject.toml with strict tooling config
- pre-commit hooks (ruff, black, mypy, bandit, detect-secrets, gitleaks)
- GitHub Actions CI skeleton (CI, CodeQL, dependency review)
- Docker Kali sandbox skeleton
- ADR template

### Security
- Default-deny scope guard design
- Destructive-action blocklist design
- JSONL hash-chained audit log design

## [0.1.0] - TBD

Initial public release (Phase 0 complete).

[Unreleased]: https://github.com/Lozens/HunterSecV1/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Lozens/HunterSecV1/releases/tag/v0.1.0
