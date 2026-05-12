# HunterSecV1 — Technical Architecture

## 1. High-level Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          User Interface                           │
│   ┌─────────────────┐                ┌────────────────────────┐   │
│   │  CLI (Typer)    │                │  Web UI (Phase 4)      │   │
│   │  - hunter htb   │                │  - FastAPI + Next.js   │   │
│   │  - hunter ctf   │                │  - WebSocket streaming │   │
│   └────────┬────────┘                └────────────┬───────────┘   │
└────────────┼─────────────────────────────────────┼───────────────┘
             │                                      │
             └──────────────┬───────────────────────┘
                            │
                ┌───────────▼────────────┐
                │   Session Manager       │
                │   - load scope          │
                │   - load budget         │
                │   - init audit logger   │
                └───────────┬────────────┘
                            │
                ┌───────────▼────────────┐
                │   Safety Pre-Filter     │
                │   - scope validation    │
                │   - rate limiter        │
                │   - blocklist check     │
                └───────────┬────────────┘
                            │
       ┌────────────────────▼────────────────────┐
       │       LangGraph Orchestrator             │
       │                                          │
       │   ┌──────────┐                           │
       │   │  ENTRY   │                           │
       │   └────┬─────┘                           │
       │        │                                 │
       │   ┌────▼─────┐    ┌─────────────┐        │
       │   │ Planner  │───▶│  Reflector  │        │
       │   │ (smart)  │◀───│  (cheap)    │        │
       │   └────┬─────┘    └─────────────┘        │
       │        │                                 │
       │   ┌────▼─────┐                           │
       │   │ Executor │───▶ Tool Registry ───────▶│──┐
       │   └────┬─────┘                           │  │
       │        │                                 │  │
       │   ┌────▼─────┐                           │  │
       │   │Validator │ (cite-required)           │  │
       │   └────┬─────┘                           │  │
       │        │                                 │  │
       │   ┌────▼─────┐                           │  │
       │   │ Reporter │                           │  │
       │   └────┬─────┘                           │  │
       │        │                                 │  │
       │   ┌────▼─────┐                           │  │
       │   │   END    │                           │  │
       │   └──────────┘                           │  │
       └──────────────────────────────────────────┘  │
                                                     │
                          ┌──────────────────────────┘
                          │
                ┌─────────▼────────────┐
                │  Sandbox Executor    │
                │  (Docker rootless)   │
                │                      │
                │  - net: isolated     │
                │  - mount: ro host    │
                │  - resource limits   │
                │  - timeout           │
                └─────────┬────────────┘
                          │
                ┌─────────▼────────────┐
                │  Audit Logger        │
                │  (JSONL append-only) │
                │  - hash-chained      │
                │  - rotated daily     │
                └──────────────────────┘
```

## 2. Module Boundaries

### `huntersec.core`
**Trách nhiệm:** Định nghĩa state machine, base agent, message protocol.
**Phụ thuộc cho phép:** `pydantic`, `langgraph`, `huntersec.safety`.
**Cấm:** Trực tiếp import LLM SDK, trực tiếp shell out. Phải đi qua abstraction.

### `huntersec.llm`
**Trách nhiệm:** LLM abstraction, provider adapters, router, caching.
**Public API:** `LLMRouter.complete(messages, model_hint=...)`.
**Cấm:** Biết về domain security. Chỉ là dumb pipe.

### `huntersec.tools`
**Trách nhiệm:** Wrap CLI tools thành Pythonic API có type-safe.
**Mỗi tool implement `BaseTool` interface:**
```python
class BaseTool(ABC):
    name: str
    category: ToolCategory  # RECON | EXPLOIT | CRYPTO | ...
    risk_level: RiskLevel   # PASSIVE | ACTIVE | INTRUSIVE
    requires_scope: bool = True
    
    @abstractmethod
    async def run(self, ctx: ToolContext) -> ToolResult: ...
    
    @abstractmethod
    def validate_input(self, args: dict) -> ValidationResult: ...
```
**Cấm:** Bypass sandbox. Tools không bao giờ chạy subprocess trực tiếp trên host.

### `huntersec.sandbox`
**Trách nhiệm:** Quản lý Docker container Kali, exec commands, stream output.
**Phụ thuộc:** `docker-py`, `aiofiles`.
**Đảm bảo:** Network namespace isolated, filesystem mount read-only, CPU/RAM limits, timeout cứng.

### `huntersec.safety`
**Trách nhiệm:** Scope validation, blocklist enforcement, audit logging, rate limiting.
**Quan trọng:** Module này được test ở mức property-based (hypothesis). Coverage ≥ 95%.

### `huntersec.solvers`
**Trách nhiệm:** High-level workflow cho từng category (HTB machine, CTF web, …).
**Style:** Mỗi solver là một `StateGraph` chuyên dụng kế thừa từ base.

### `huntersec.memory`
**Trách nhiệm:** Vector DB cho retrieval (HackTricks, GTFOBins, past runs).
**Storage:** SQLite + sqlite-vec extension. Local-first.

### `huntersec.reporting`
**Trách nhiệm:** Render markdown / PDF / HTML report từ session state.

### `huntersec.cli`
**Trách nhiệm:** Typer commands. Layer mỏng — không chứa business logic.

## 3. Dataflow một lệnh điển hình

User: `hunter htb solve --target 10.10.11.42 --machine "Sample"`

1. `cli/commands/htb.py` parse args → tạo `Session` object
2. `SessionManager` load `scope.yaml` → validate `10.10.11.42` trong scope HTB (10.10.0.0/16)
3. `AuditLogger` khởi tạo file `data/audit/2026-05-11_<sessionid>.jsonl`, ghi event `session.start`
4. `solvers.htb.HTBSolver` build LangGraph và `invoke(initial_state)`
5. **Planner node:** gọi `LLMRouter.complete(...)` → trả về plan dạng JSON `{steps: [{tool, args, rationale}]}`
6. **Executor node:** với mỗi step:
   - `SafetyFilter.check(tool, args)` → pass/block
   - `ToolRegistry.get(tool).run(ctx)` → `SandboxExecutor.exec_in_container(cmd)`
   - Capture stdout/stderr → ghi vào audit log
7. **Validator node:** LLM đọc output, ép quote evidence, classify "useful / noise / suspicious"
8. **Reflector** (cheap LLM): có cần re-plan? loop back hoặc tiến tới reporter
9. **Reporter:** sinh `data/reports/<sessionid>.md`
10. Audit log đóng với hash final

## 4. Threat Model (của chính tool)

| Threat | Asset | Mitigation |
|---|---|---|
| Prompt injection từ tool output | Agent decision | Strip control chars, sandbox parse, never `eval` LLM output |
| LLM bị nhử thực thi lệnh nguy hiểm | Host system | Blocklist + sandbox + dry-run default |
| Container escape | Host | Rootless docker, gVisor, seccomp profile, no `--privileged` |
| Secrets leak qua audit log | API keys | Mask patterns trước khi log (regex + named entity) |
| Out-of-scope attack | Target hợp pháp | Hard-coded scope file gate trước mỗi network call |
| Token cost spike | Wallet | LLM router budget cap per session, hard kill nếu vượt |
| Supply chain (malicious dep) | Codebase | Pin versions + lockfile + `pip-audit` + Dependabot |
| Tampered audit log | Forensic integrity | Hash chain (mỗi entry chứa hash entry trước) |

## 5. Configuration Layers

Thứ tự override (sau ghi đè trước):
1. Built-in defaults (`huntersec/config/defaults.yaml`)
2. System config (`/etc/huntersec/config.yaml`)
3. User config (`~/.config/huntersec/config.yaml`)
4. Project config (`./.huntersec.yaml`)
5. Environment variables (`HUNTERSEC_*`)
6. CLI flags

**Tuyệt đối** không hard-code secrets. Dùng `HUNTERSEC_ANTHROPIC_API_KEY` style env vars hoặc OS keyring.

## 6. Extension Points

- **Custom tool:** subclass `BaseTool`, đặt trong `~/.huntersec/plugins/`, agent auto-discover qua entry_points.
- **Custom LLM provider:** implement `LLMProvider` ABC, register qua `pyproject.toml` plugins.
- **Custom solver:** subclass `BaseSolver`, đăng ký với `@register_solver("name")`.
- **Custom report template:** Jinja2 templates trong `~/.huntersec/templates/`.

## 7. Performance Budget

| Operation | Budget |
|---|---|
| CLI cold start | < 500ms |
| Single tool call (nmap fast) | < 5s overhead beyond tool |
| LLM call P95 | < 8s (cloud), < 30s (local) |
| Memory baseline | < 200MB Python process |
| Sandbox container start | < 2s (warm pool) |

## 8. Observability

- **Structured logging:** `structlog` JSON output, level configurable.
- **Metrics:** OpenTelemetry traces (opt-in), Prometheus export endpoint trong Web UI.
- **Tracing decisions:** Mỗi LangGraph node lưu input/output vào audit log.
- **Token accounting:** Real-time counter per session, hiển thị trên CLI status bar.
