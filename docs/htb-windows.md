# Running HunterSecV1 against HackTheBox on Windows

Docker Desktop on Windows (WSL2 backend) **does not support `--network host`**
the way native Linux does. The container's bridge network is NAT'd through
the Windows host's default route, **not** through the OpenVPN `tun0`
interface used by the HackTheBox VPN.

Symptom: the sandbox container can't ping `10.10.x.x` / `10.129.x.x` even
though the host can. Every recon tool returns "0 hosts up" or times out.

You have two supported workarounds:

## Option 1 — Run from inside WSL2 with host networking (recommended)

WSL2 supports `--network host` for Docker because it's a Linux kernel.

1. Open a WSL2 distribution (Ubuntu, Debian, Kali-WSL, …).
2. Install the HTB VPN client inside WSL2:
   ```bash
   sudo apt update && sudo apt install -y openvpn
   ```
3. Connect to HTB:
   ```bash
   sudo openvpn /path/to/lab_<user>.ovpn
   ```
   Leave that terminal open. Verify with `ip a show tun0` and
   `ping 10.10.x.x`.
4. In a second WSL2 terminal, navigate to the project and run with host
   networking:
   ```bash
   cd /mnt/c/Users/<you>/OneDrive/Desktop/HunterSecV1
   source .venv/bin/activate
   hunter htb solve \
       --target 10.10.11.42 \
       --scope configs/scope.yaml \
       --network host \
       --execute
   ```

The `--network host` flag wires the sandbox's `network_mode` setting to
`"host"`, so `docker run --network host` is emitted and the container
shares WSL2's `tun0` route.

⚠ **Trade-off**: `--network host` removes a sandbox boundary. The
container still drops all capabilities, runs as a non-root user, and uses
a read-only rootfs, but it can now reach any service the host can reach
(including localhost on the host). Only use this for authorised testing
on isolated VMs / VPN networks.

## Option 2 — Run the tools directly on the Windows host

If you prefer not to set up WSL2 networking, you can install the recon
binaries on Windows itself and bypass Docker. **Note this loses sandbox
isolation entirely** and is not officially supported by HunterSecV1's
safety story — use only on a disposable / VM Windows install you control.

Install:
- [Nmap for Windows](https://nmap.org/download.html)
- [Gobuster](https://github.com/OJ/gobuster/releases) (extract to `PATH`)
- [httpx](https://github.com/projectdiscovery/httpx/releases)

HunterSecV1 does not yet expose a "no-Docker" execution mode in the CLI;
you'd need to call tools directly from PowerShell. We recommend Option 1.

## Option 3 — Use a Linux host or Linux VM

The cleanest path: install Linux (any distribution with Docker Engine,
not Docker Desktop) and run HTB VPN + HunterSecV1 there. `--network host`
just works.

---

## How `--network` flag flows through the code

- `hunter htb solve --network host` → `SandboxSettings(network_mode="host")`
- `SandboxExecutor._build_docker_argv` emits `--network host`
- The CLI prints a warning to stderr so the operator knows isolation is
  reduced for this session.

Allowed values: `bridge` (default), `internal`, `none`, `host`.
