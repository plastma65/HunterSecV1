# HunterSecV1

> **Autonomous offensive-security agent — ethical, opensource, multi-LLM.**

[![CI](https://github.com/plastma65/HunterSecV1/actions/workflows/ci.yml/badge.svg)](https://github.com/plastma65/HunterSecV1/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

HunterSecV1 là agent AI tự động giải các bài lab pentest, CTF, và hỗ trợ workflow bug bounty hợp pháp. Lấy cảm hứng từ PentestGPT và HexStrike-AI, nhưng đặt **an toàn và đạo đức làm core** thay vì afterthought.

> ⚠️ **Ethical use only.** Đọc [`docs/ethics.md`](docs/ethics.md) trước khi dùng. Tool này KHÔNG được sử dụng cho hoạt động trái phép.

---

## Tính năng

- 🤖 **Multi-LLM router** — Claude, OpenAI, Gemini, Ollama. Tự chọn model tối ưu chi phí/chất lượng.
- 🐳 **Docker Kali sandbox** — Mọi command chạy trong container isolated, không bao giờ touch host.
- 🛡️ **Safety-first** — Scope guard, destructive-action blocklist, JSONL audit log hash-chained.
- 🎯 **Specialized solvers** — HTB machine, THM room, CTF challenge (Web/Crypto/Reverse/Pwn/Forensics).
- 📊 **Markdown reports** — Reproducible PoC kèm timeline.
- 🔌 **Extensible** — Plugin system cho tools, LLM providers, solvers.

---

## Quick Start

```bash
# Yêu cầu: Python 3.11+, Docker, uv (https://github.com/astral-sh/uv)

git clone https://github.com/plastma65/HunterSecV1.git
cd HunterSecV1
make setup            # cài deps + pre-commit hooks
make sandbox          # build Kali Docker image (lần đầu ~ 5 phút)

# Cấu hình LLM provider (chọn ít nhất 1):
export HUNTERSEC_ANTHROPIC_API_KEY="sk-ant-..."
# hoặc
export HUNTERSEC_OPENAI_API_KEY="sk-..."
# hoặc dùng local Ollama
ollama pull qwen2.5:14b

# Tạo scope file cho mục tiêu hợp lệ (HTB lab subnet ví dụ):
cp configs/scope.example.yaml configs/scope.yaml

# Chạy
hunter --help
hunter htb solve --target 10.10.11.42
hunter ctf solve --category web --challenge ./chal.tar.gz
```

### Running on Windows with HTB VPN

Docker Desktop trên Windows không hỗ trợ `--network host`, nên sandbox
container **không reach được HTB VPN** từ bridge mặc định. Hai phương án
được hỗ trợ:

1. **Chạy từ WSL2** (recommended): kết nối OpenVPN trong WSL2, dùng
   `hunter htb solve ... --network host --execute`.
2. **Chạy trên Linux host hoặc Linux VM**.

Chi tiết: [`docs/htb-windows.md`](docs/htb-windows.md).

---

## Architecture (1-paragraph)

User → CLI/Web → Safety pre-filter (scope, blocklist, rate-limit) → LangGraph orchestrator (Planner → Executor → Validator → Reporter nodes) → Tool registry → Docker sandbox (Kali). Mọi action ghi vào audit log JSONL hash-chained. LLM Router multi-provider phía sau. Memory layer dùng SQLite + sqlite-vec cho retrieval (HackTricks, GTFOBins).

Chi tiết: [`docs/architecture.md`](docs/architecture.md).

---

## Roadmap

| Phase | Mục tiêu | Status |
|---|---|---|
| 0 — Foundation | Repo, CI, audit log, CLI skeleton | 🚧 In progress |
| 1 — Core Agent | LLM router, LangGraph loop, 5 recon tools | ⏳ Planned |
| 2 — HTB/THM Solver | Solve ≥ 3 easy machines tự động | ⏳ Planned |
| 3 — CTF Solver | Solve ≥ 60% easy CTF challenges | ⏳ Planned |
| 4 — Web UI | FastAPI + Next.js dashboard | ⏳ Planned |
| 5 — Bug Bounty Mode | Scope-aware recon automation | ⏳ Planned |

Roadmap chi tiết: [`docs/plan.md`](docs/plan.md).

---

## Contributing

Xem [`CONTRIBUTING.md`](CONTRIBUTING.md) để biết quy trình đóng góp. PR welcome, đặc biệt:

- Tool wrappers mới (nmap-like CLI tool wrappers)
- LLM provider adapters
- Solver chiến lược cho machine/CTF mới
- Documentation, examples, benchmarks

Mọi contributor đồng ý với [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) và [`docs/ethics.md`](docs/ethics.md).

---

## Security

Phát hiện lỗ hổng trong HunterSecV1? Xem [`SECURITY.md`](SECURITY.md) cho responsible disclosure process.

**KHÔNG** mở public issue cho security vulnerability.

---

## License

[Apache License 2.0](LICENSE) — see file for details.

This software is provided "as is", without warranty. Authors and contributors are not liable for misuse. See `docs/ethics.md` for acceptable use.

---

## Acknowledgments

- [PentestGPT](https://github.com/GreyDGL/PentestGPT) — inspiration, paper
- [LangGraph](https://github.com/langchain-ai/langgraph) — agent state machine
- [HackTricks](https://book.hacktricks.xyz/), [GTFOBins](https://gtfobins.github.io/) — knowledge base
- [HackTheBox](https://www.hackthebox.com/), [TryHackMe](https://tryhackme.com/) — lab platforms

---

**Maintainer:** [@plastma65](https://github.com/plastma65) · trantuananh.businessman@gmail.com
