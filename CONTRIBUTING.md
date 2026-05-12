# Contributing to HunterSecV1

Cảm ơn bạn quan tâm đến HunterSecV1! Đọc kỹ trước khi bắt đầu.

## Trước khi đóng góp

1. Đọc [`CLAUDE.md`](CLAUDE.md) — bộ quy tắc engineering bắt buộc.
2. Đọc [`docs/ethics.md`](docs/ethics.md) — chính sách sử dụng có đạo đức.
3. Đọc [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — kỳ vọng hành vi cộng đồng.
4. Lướt [`docs/plan.md`](docs/plan.md) và [`docs/architecture.md`](docs/architecture.md) để hiểu bigger picture.

## Loại đóng góp

- **Bug fix** — luôn welcome.
- **Tool wrapper** — wrap thêm CLI tool (nikto, sqlmap, ffuf, …) theo `BaseTool` interface.
- **LLM provider** — adapter mới cho LLM SDK.
- **Solver strategy** — chiến lược giải machine/CTF mới.
- **Documentation** — fix typo, thêm tutorial, dịch.
- **Test** — adversarial cases, fuzzing, benchmarks.

## Workflow

1. **Issue first** — mở issue trước khi viết code lớn (> 100 LoC). Discuss design.
2. **Fork & branch** — branch name theo §4.1 của `CLAUDE.md`.
3. **Code** — tuân thủ style §2 và testing §3 của `CLAUDE.md`.
4. **Pre-commit** — `pre-commit run --all-files` phải pass.
5. **Test** — `make test` phải xanh; thêm test cho code mới.
6. **PR** — fill template, link issue, kiểm tra checklist.
7. **Review** — phản hồi review trong 7 ngày hoặc PR có thể bị đóng.
8. **Merge** — sau khi CI xanh + ≥ 1 approve.

## Dev environment

```bash
git clone https://github.com/Lozens/HunterSecV1.git
cd HunterSecV1
make setup
source .venv/bin/activate

# Verify
make lint test
hunter --help
```

Yêu cầu:
- Python 3.11+
- Docker (cho integration tests)
- uv (`pipx install uv`)
- Git ≥ 2.30

## Style cheat sheet

| Aspect | Rule |
|---|---|
| Formatter | `black` (100 cols) |
| Linter | `ruff` strict |
| Types | `mypy --strict` |
| Commits | Conventional Commits |
| Docstrings | Google style |
| Tests | pytest, AAA, ≥ 80% cov overall |
| Imports | absolute từ `huntersec.*` |

## Đặc biệt cho contribution có tính tấn công (offensive primitive)

Nếu PR thêm capability liên quan thực thi exploit, fuzz network, parse adversarial input:

1. Mở issue mô tả use case hợp pháp (CTF? HTB? bug bounty class?).
2. Bao gồm test với target lab giả (RFC reserved IPs, hosts.txt với example.com).
3. Cập nhật scope guard / blocklist nếu cần.
4. Reviewer sẽ áp dụng tiêu chí "có thể abuse dễ không?" — nếu yes, cần safeguard mạnh hơn.

## Communication

- **Discussions** — câu hỏi mở, đề xuất ý tưởng
- **Issues** — bug, feature đã rõ requirement
- **Discord/Matrix** — (TBD, sẽ thêm khi community lớn hơn)
- **Email** — riêng tư, security-related

## Recognition

Mọi contributor merge ≥ 1 PR sẽ được liệt kê ở `CONTRIBUTORS.md` (auto-generated từ git history).

## License

Bằng việc submit PR, bạn đồng ý licensing code dưới [Apache License 2.0](LICENSE) — không có CLA bổ sung.
