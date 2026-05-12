# HunterSecV1 — Master Plan & Roadmap

> **Tài liệu này là nguồn chân lý (source of truth) cho định hướng dự án. Mọi quyết định lớn phải tham chiếu lại đây hoặc tạo ADR mới nếu thay đổi.**

---

## 1. Tầm nhìn (Vision)

HunterSecV1 là một **autonomous offensive-security agent** mã nguồn mở, được thiết kế để:

1. Tự động giải các bài lab pentest trên HackTheBox, TryHackMe và các nền tảng tương đương.
2. Tự động giải các challenge CTF (Web, Crypto, Reverse, Pwn, Forensics, OSINT).
3. Hỗ trợ workflow bug bounty hợp pháp với scope guard nghiêm ngặt.
4. Hoạt động như một copilot tương tác cho pentester / red teamer.

**Cam kết đạo đức:** Dự án này **không** hỗ trợ và **chủ động chặn** các hành vi tấn công ngoài scope, hành vi phá hoại (DDoS, ransomware), hoặc bất kỳ hoạt động bất hợp pháp nào. Xem `docs/ethics.md`.

---

## 2. So sánh và định vị

| Dự án | Điểm mạnh | Điểm yếu | HunterSecV1 khác biệt thế nào? |
|---|---|---|---|
| **PentestGPT** | Pioneer, có paper academic | Single-LLM, không có sandbox, prompt-only | Có sandbox Docker, multi-provider, multi-agent workflow |
| **HexStrike-AI** | Nhiều tool integration | Đóng nguồn một phần, chưa stable | Mã nguồn mở hoàn toàn, có scope guard, audit log |
| **WormGPT** (gốc) | (Malicious) | Bị banned, có hại | KHÔNG so sánh — HunterSecV1 là phiên bản đạo đức |
| **AutoGPT/AgentGPT** | General agent | Không chuyên security | Domain-specific cho security, có tool wrappers chuyên dụng |

**Khác biệt cốt lõi của HunterSecV1:**
- **Safety-first by design** — không phải bolt-on
- **Multi-LLM router** — không khoá vendor
- **Sandbox enforced** — không bao giờ chạy lệnh trực tiếp trên host
- **Audit trail JSONL** — full forensic replay
- **LangGraph state machine** — workflow rõ ràng, có thể debug

---

## 3. Kiến trúc tổng thể (Tóm tắt)

```
┌─────────────────────────────────────────────────────────────┐
│                       USER (CLI / Web UI)                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                  ┌────────────▼────────────┐
                  │   Safety Pre-Filter     │  ← scope.yaml, blocklist
                  └────────────┬────────────┘
                               │
        ┌──────────────────────▼──────────────────────┐
        │       Orchestrator (LangGraph StateGraph)    │
        │  ┌─────────┐ ┌─────────┐ ┌─────────┐         │
        │  │ Planner │→│ Executor│→│Validator│         │
        │  └─────────┘ └─────────┘ └─────────┘         │
        └──────────────────────┬──────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │  LLM Router │   │Tool Registry│   │   Memory   │
       │ (Multi-prov)│   │(Kali tools) │   │ (vector DB)│
       └────────────┘   └─────┬──────┘   └────────────┘
                              │
                  ┌───────────▼───────────┐
                  │  Docker Sandbox (Kali) │
                  │   - network isolated   │
                  │   - read-only host fs  │
                  └───────────┬───────────┘
                              │
                  ┌───────────▼───────────┐
                  │   Audit Log (JSONL)    │
                  └───────────────────────┘
```

Chi tiết kiến trúc xem `docs/architecture.md`.

---

## 4. Roadmap theo phase

### Phase 0 — Foundation (Tuần 1–3)

**Mục tiêu:** Có repo public, CI xanh, agent loop tối thiểu trả lời được "list scope hiện tại".

- [ ] Tạo repo public GitHub `HunterSecV1` (Apache 2.0)
- [ ] Setup pre-commit (ruff, black, mypy, bandit, detect-secrets)
- [ ] Setup GitHub Actions: `ci.yml` (lint + test), `codeql.yml`, `dependabot`
- [ ] Viết `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`
- [ ] Setup `pyproject.toml` với `uv` hoặc `poetry`
- [ ] Tạo Docker image `huntersec/kali:slim` (Kali base + đặt sẵn tools cần thiết)
- [ ] Implement audit log writer (JSONL append-only) — đây là MUST có trước khi viết bất kỳ tool nào
- [ ] Skeleton CLI bằng Typer (`hunter --help` hoạt động)

**Definition of Done (DoD):**
- `git clone` + `make setup` + `hunter version` chạy được trên Linux/macOS/WSL
- CI badge xanh trên README

---

### Phase 1 — Core Agent (Tuần 4–9)

**Mục tiêu:** Agent có thể nhận một mục tiêu trong scope, chạy nmap recon, viết report markdown.

- [ ] LLM abstraction layer (`llm/base.py`) với adapters cho Anthropic, OpenAI, Gemini, Ollama
- [ ] LLM Router với cost/quality routing (cheap LLM cho classification, smart LLM cho exploit reasoning)
- [ ] LangGraph state machine: `planner → executor → validator → reporter`
- [ ] Tool Registry (dynamic discovery) — mỗi tool là một subclass `BaseTool`
- [ ] Wrappers cho 5 tools đầu tiên: `nmap`, `gobuster`, `ffuf`, `whatweb`, `httpx`
- [ ] Safety layer:
  - `scope.py` — parse `scope.yaml`, validate target trước mỗi tool call
  - `blocklist.py` — chặn destructive commands (`rm -rf /`, `dd if=`, fork bomb, DDoS patterns…)
  - `audit.py` — JSONL log với hash chain (tamper-evident)
- [ ] Memory layer (SQLite + sentence-transformers cho local vector search)
- [ ] Markdown report generator

**DoD:**
- Demo video: agent recon một target trong scope HTB lab, sinh report .md
- Unit test coverage ≥ 70% cho `safety/` và `llm/`

---

### Phase 2 — HTB/THM Machine Solver (Tuần 10–17)

**Mục tiêu:** Solve được ≥ 3 machines easy của HTB và ≥ 5 rooms của THM mà không cần human intervention.

- [ ] Specialized sub-agents:
  - `recon_agent` — enumeration toàn diện
  - `web_agent` — directory brute, param fuzz, common CVEs
  - `service_agent` — protocol-specific (SMB, FTP, SSH, RDP)
  - `exploit_agent` — chọn và adapt exploit
  - `privesc_agent` — linpeas/winpeas parsing, GTFOBins lookup
- [ ] Knowledge base: GTFOBins, HackTricks (offline mirror, có cache + update script)
- [ ] Tool wrappers thêm: `metasploit` (RPC), `searchsploit`, `linpeas`, `winpeas`, `enum4linux-ng`, `kerbrute`, `impacket-*`
- [ ] HTB API integration (đọc machine info, submit flag — opt-in, user phải provide token)
- [ ] THM integration tương tự
- [ ] Benchmark suite: tracking success rate / time / token cost trên một danh sách retired machines

**DoD:**
- Bảng benchmark public trong README
- Reproducible run với `hunter htb solve <machine-name>`

---

### Phase 3 — CTF Solver (Tuần 18–25)

**Mục tiêu:** Solve được challenge mỗi category ở level Easy/Medium.

- [ ] Web category: SQLi, XSS, SSTI, SSRF, IDOR, file upload, race condition
  - Tools: `sqlmap`, `nuclei`, custom python exploit scripts
- [ ] Crypto category: classical ciphers, RSA quirks, AES modes, hashing
  - Libs: `pycryptodome`, `gmpy2`, `sage` (optional)
- [ ] Reverse category: static + dynamic analysis assist
  - Tools: `ghidra` headless, `radare2`, `r2pipe`, `angr`, `pwntools`
- [ ] Pwn category: stack overflow, format string, ROP đơn giản
  - Tools: `pwntools`, `ROPgadget`, `one_gadget`, `gdb` (pwndbg)
- [ ] Forensics: file carving, metadata, network pcap analysis
  - Tools: `binwalk`, `foremost`, `volatility3`, `wireshark`/`tshark`, `exiftool`
- [ ] OSINT (bonus): có giới hạn rõ ràng, không scraping PII trái phép

**DoD:**
- Solve ≥ 60% challenges trong public CTF dataset (picoCTF, HTB Starting Point CTF)
- Report PoC reproducible

---

### Phase 4 — Web UI & Polish (Tuần 26–32)

**Mục tiêu:** Người không quen CLI cũng dùng được, demo đẹp cho recruiter.

- [ ] Backend: FastAPI với WebSocket cho streaming agent thought
- [ ] Frontend: Next.js + shadcn/ui + xterm.js
  - Dashboard: scope manager, active jobs, audit log viewer
  - Agent inspector: state graph viz (mermaid live), token usage
  - Report library
- [ ] Auth: OAuth (GitHub) cho self-hosted multi-user
- [ ] Deployable: `docker compose up` chạy được full stack

**DoD:**
- Hosted demo (read-only mode) trên Cloudflare Tunnel hoặc Fly.io
- Tutorial video 5 phút

---

### Phase 5 — Bug Bounty Mode (Tuần 33+, ongoing)

**Mục tiêu:** Hỗ trợ workflow bug bounty với guarantees an toàn pháp lý.

- [ ] HackerOne / Bugcrowd / Intigriti scope import (manual paste hoặc API nếu có)
- [ ] Recon automation: subdomain enum, JS analysis, ASN lookup, content discovery
- [ ] Vulnerability triage assistant: deduplicate, severity scoring (CVSS auto-suggest)
- [ ] Report drafting cho từng platform format
- [ ] **Rate limiting bắt buộc**, **scope re-validation trước mỗi request**, **dry-run là default**

**DoD:**
- Disclosed report đầu tiên với platform partner (ưu tiên program có safe harbor)

---

## 5. Tech stack chi tiết

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | Ecosystem security, AI libs |
| Agent framework | LangGraph | State machine rõ ràng, debugger tốt |
| LLM SDK | `anthropic`, `openai`, `google-genai`, `ollama` | Multi-provider, abstracted qua `llm/router.py` |
| CLI | Typer + Rich | Đẹp, type-safe |
| HTTP | httpx | Async + sync, hơn requests |
| Web framework (Phase 4) | FastAPI | Async, OpenAPI auto-gen |
| Frontend (Phase 4) | Next.js 15 + shadcn/ui + xterm.js | Modern, đẹp portfolio |
| Vector DB | sqlite-vec + sentence-transformers | Embedded, no server |
| Test | pytest + pytest-asyncio + hypothesis | Property-based cho safety |
| Lint/Format | ruff + black + mypy --strict | Strict mode |
| Security lint | bandit, semgrep, detect-secrets | Run trong CI |
| Sandbox | Docker (rootless + gVisor optional) | Network-isolated |
| Packaging | uv (10x nhanh hơn pip) | Modern Python |
| Docs | mkdocs-material | Đẹp, host trên GH Pages |

---

## 6. Risk & Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Agent tự ý attack ngoài scope | Pháp lý nghiêm trọng | Hard-coded scope guard, dry-run default, audit log + alert |
| Token cost vượt budget | Financial | LLM router với budget cap, cheap-LLM fallback, cache aggressively |
| LLM hallucination → exploit sai | Lãng phí time | Validator node ép cite source, executor double-check |
| Maintenance burden cao | Burnout | Modular tool plugins, community PR, dependabot |
| Bị abuse cho mục đích xấu | Reputation, pháp lý | License terms + ETHICS.md + code of conduct enforced, scope-mandatory mode default |
| Tools downstream broken (Kali update) | CI red | Pin Docker image tag, weekly nightly build |

---

## 7. KPIs đo lường thành công

**Technical:**
- HTB easy machine solve rate ≥ 60%
- HTB medium machine solve rate ≥ 30%
- CTF easy challenge solve rate ≥ 70%
- Mean time-to-foothold < 30 phút trên easy
- Test coverage ≥ 80% module safety, ≥ 60% overall

**Community:**
- ≥ 100 GitHub stars trong 6 tháng đầu
- ≥ 5 external contributors
- ≥ 1 mention từ infosec influencer / blog

**Portfolio:**
- 1 conference talk hoặc blog post technical deep-dive
- 1 disclosed bug bounty report public sử dụng tool

---

## 8. Workflow phát triển

1. **Plan trên Claude Desktop:** brainstorm, viết doc, vẽ architecture (file ở `docs/`)
2. **Code trên Claude Code:** implement theo `CLAUDE.md` rules, mỗi feature một branch
3. **PR review:** human + Claude code review trước khi merge
4. **CI:** lint → unit test → integration test → security scan → build Docker
5. **Release:** semver, changelog auto-gen từ conventional commits

Chi tiết git workflow xem `CLAUDE.md` mục **Git & PR Workflow**.

---

## 9. Tài liệu tham khảo

- [PentestGPT paper (Deng et al., 2023)](https://arxiv.org/abs/2308.06782)
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [HackTheBox Academy](https://academy.hackthebox.com/)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)

---

**Phiên bản tài liệu:** 0.1.0
**Cập nhật cuối:** 2026-05-11
**Maintainer:** Lozens
