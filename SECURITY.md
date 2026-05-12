# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (pre-alpha) | Yes — current development line |
| < 0.1.0 | No |

The first stable release (1.0.0) will define a clear LTS policy.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

### Channels (in order of preference)

1. **GitHub Security Advisories** — preferred: <https://github.com/Lozens/HunterSecV1/security/advisories/new>
2. **Email** — `trantuananh.businessman@gmail.com` with subject prefix `[HunterSecV1 SECURITY]`. Please consider encrypting with the maintainer's PGP key if available.

### What to include

- Affected version / commit hash
- Reproduction steps (minimal PoC)
- Impact assessment (confidentiality / integrity / availability)
- Suggested fix if you have one
- Your contact info + how you'd like to be credited

### Response timeline

- **24 hours** — acknowledgement of receipt
- **7 days** — initial triage + severity rating
- **30 days** — fix in private branch (Critical/High); 90 days for Medium/Low
- **Coordinated disclosure** — once fix is published, public CVE + advisory

### Scope

**In-scope:**
- Code in this repository
- Default configurations shipped in `configs/`
- Docker images published under the project namespace
- Documentation that could mislead users into insecure usage

**Out of scope:**
- Vulnerabilities in third-party tools wrapped by HunterSecV1 (report upstream)
- Vulnerabilities in lab platforms (HackTheBox, TryHackMe — report to them)
- Issues in user-supplied custom plugins
- Findings that require a malicious actor to already have local user privileges

### Safe Harbor

We will not pursue legal action against researchers who:
- Engage in good-faith research within scope above
- Do not exploit beyond proof-of-concept on their own resources
- Do not disclose to third parties before coordinated disclosure
- Do not perform attacks on infrastructure of contributors or users

## Hall of Fame

Once we receive our first valid reports, we will list reporters here (with consent).

## Notes on Tool Misuse

This project is itself an offensive-security tool. We are committed to making it hard to misuse:

- Default-deny scope guard
- Destructive-action blocklist
- Hash-chained audit log
- No phone-home / no telemetry by default

If you find a way to **bypass these safeguards**, please report through the channels above — bypassing safety controls is treated as a Critical severity issue.

If you observe HunterSecV1 being used for unauthorized attacks, see `docs/ethics.md` §5.
