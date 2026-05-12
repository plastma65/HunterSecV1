## Summary

<!-- 1-3 bullet points: what changed and why -->

- 
- 

## Related issue

Closes #

## Type of change

- [ ] feat: new feature
- [ ] fix: bug fix
- [ ] security: security improvement
- [ ] refactor: code refactoring (no behaviour change)
- [ ] test: test additions / fixes
- [ ] docs: documentation only
- [ ] chore: tooling, CI, dependencies

## Checklist

- [ ] `make lint` passes (ruff + mypy + bandit)
- [ ] `make test` passes, coverage did not drop
- [ ] Type checker `mypy --strict` is green on changed files
- [ ] Docs updated if public API changed
- [ ] CHANGELOG entry added
- [ ] If touched `safety/`: adversarial test cases added
- [ ] If added a tool: `docs/tools.md` updated with risk classification
- [ ] If changed a prompt: before/after bench comparison attached (if feasible)
- [ ] PR size < 400 LoC changed (excluding generated / lockfiles)
- [ ] No hard-coded secrets, API keys, or real-world target IPs

## Safety checklist (required if touching `huntersec/safety/` or sandbox)

- [ ] No bypass of `huntersec.safety` in any code path
- [ ] No `subprocess.run(..., shell=True)` added
- [ ] No `eval()` / `exec()` of external input
- [ ] Security-relevant events logged via `AuditLogger`
- [ ] Adversarial test cases cover: path traversal, command injection, prompt injection

## Test plan

<!-- Describe how you tested this. Link to test files if new. -->

```
pytest tests/unit/test_<module>.py -v
```

## Notes for reviewer

<!-- Anything the reviewer should know: non-obvious decisions, known limitations, follow-up issues. -->
