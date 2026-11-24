# ⚡ phantom-ssh

> **Next-Generation High-Speed SSH Spraying, Anti-Fail2ban Evasion & Real-Time Hardware Triager**

`phantom-ssh` is an elite, high-performance credential spraying engine built in modern Go. It is engineered specifically for large-scale security assessments, adversary simulations, and rapid infrastructure qualification. Designed to overcome the fatal bottlenecks of legacy SSH sprayers—such as Fail2ban IP bans, Endlessh tarpits, Cowrie honeypot poisoning, and memory bloat.

---

## 🚀 Key Advantages Over Legacy Sprayers

| Feature | Legacy Sprayers (`ssh.go` / Hydras) | **`phantom-ssh`** |
| :--- | :--- | :--- |
| **Fail2ban Evasion** | Tight-loop attacks on same IP → Banned in 3 tries | **Horizontal spray + Subnet interleaving + Max attempts guard** |
| **Client Signature** | Exposes default `SSH-2.0-Go` banner (easily blocked) | **Dynamic OpenSSH masquerading (`SSH-2.0-OpenSSH_9.3p1`)** |
| **Honeypot Detection** | Misses modern Cowrie/Kippo or floods goods with fakes | **Canary traps + POSIX arithmetic check + ANSI filter + Procfs** |
| **Tarpits (Endlessh)** | Hangs worker threads on infinite slow byte trickles | **Strict pre-banner TCP read deadlines (< 2s drop)** |
| **Hardware Triage** | Slow multi-roundtrip commands (10–15s per hit) | **Single-shot sub-150ms compound inspection pipeline** |
| **Input Format** | Requires manual parsing of IP / port lists | **Direct intake of `phantom-scan` outputs (`SSH.txt`)** |
| **Resource Usage** | Pre-allocates $O(N \times M)$ combinations in RAM | **Streaming worker queue with zero-allocation buffers** |

---

## 🛡️ Fail2ban & Rate-Limit Evasion Engine

Fail2ban, CrowdSec, and standard IDS systems typically trigger after **3 to 5 failed logins within a 10-minute window** on a target host or subnet. `phantom-ssh` completely avoids triggering these defenses through four core mechanisms:

1. **Horizontal Target Spraying**:
   - `phantom-ssh` tests Credential #1 across **all** targets before attempting Credential #2 on any target.
   - When spraying 10,000 hosts, thousands of seconds elapse before Target #1 is revisited, exceeding the Fail2ban `findtime` window.
2. **Subnet /24 Interleaving (`--interleave`)**:
   - Grouping and shuffling targets across distinct `/24` (IPv4) or `/48` (IPv6) subnets so no two consecutive probes touch the same network prefix.
3. **Hardened Max Attempts Guard (`--max-tries 2`)**:
   - A thread-safe tracker halts further attempts on any host that hits the configured threshold (default: 2), ensuring your source IP is never blacklisted.
4. **Adaptive Micro-Jitter (`--jitter <ms>`)**:
   - Randomizes probe intervals to defeat frequency-based heuristics.

---

## 🍯 Multi-Tier Honeypot Elimination

Never waste time on fake shells or catch-all honeypots:

- **Tier 1: Pre-Auth Signature & Banner Profiling**:
  - Drops static Cowrie, Kippo, Dionaea, and Honeytrap banners.
- **Tier 2: Universal Canary Trap (`--canary-check`)**:
  - Automatically verifies successful logins by testing a randomized, non-existent canary credential. If the server accepts both, it is flagged as a 100% synthetic catch-all honeypot and discarded.
- **Tier 3: POSIX Shell Arithmetic & Environment Validation**:
  - Executes a single-shot verification script evaluating bash parameter arithmetic `$((43981+21437))` $\to$ `65418`. Python-based emulated shells fail this test immediately.
  - Inspects `/proc/version` fidelity, detects ANSI terminal reset sequences (`\x1b[H\x1b[J`), and flags Cowrie kernel mock signatures (`3.2.0-4-amd64`).

---

## ⚡ Zero-Roundtrip Post-Exploitation Triage

Upon authenticating to a verified real Linux server, `phantom-ssh` executes a unified, non-interactive pipeline in **one round trip (<150ms)** to harvest full hardware and privilege specifications:

- **Privilege Level**: Detects `UID=0` (Root) or passwordless `sudo`.
- **CPU Cores**: Multi-core processor identification via `nproc` / `/proc/cpuinfo`.
- **RAM Capacity**: Total physical memory in MB.
- **Hardware Acceleration**: Automatic discovery of NVIDIA / AMD / Tesla GPUs via `lspci`.
- **Storage**: Primary mount disk total and free capacity.
- **OS & Kernel**: Distro identification from `/etc/os-release` and `uname -r`.

### Real-Time Categorized Output Directory (`./results/`):
- `goods.txt` — Standard clean list: `IP:PORT:USER:PASS`
- `root.txt` — Systems with confirmed root or passwordless sudo rights
- `gpu.txt` — Systems with dedicated GPU compute units (RTX, A100, etc.)
- `high_ram.txt` — High-memory systems ($\ge 16$ GB RAM)
- `detailed.txt` — Complete telemetry card for each verified hit
- `honeypots.txt` — Disqualified honeypots with breakdown scores

---

## 🖥️ Live TUI Dashboard

```
╔════════════════════════════════════════════════════════════════════════════╗
║      ⚡ PHANTOM-SSH v1.0.0 — Elite Stealth SSH Sprayer & Triager ⚡         ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Elapsed: 00:01:45 | ETA: 00:03:12 | Speed: 421.8 checks/s                 ║
║  [████████████████████░░░░░░░░░░░░░░░░░░░░]  48.2% (48,200 / 100,000)      ║
╠════════════════════════════════════════════════════════════════════════════╣
║  ✅ Goods: 24 | 🍯 Honeypots: 11 | ❌ Fails: 48,012 | 🛡️ F2B Guarded: 153   ║
╠════════════════════════════════════════════════════════════════════════════╣
║  📡 Live Real-Time Hits & Telemetry:                                       ║
║  [✅ HIT] 104.21.84.12:22 | root:toor | ROOT | Ubuntu 22.04 | 16C/32GB/GPU  ║
║  [✅ HIT] 185.190.22.4:22 | admin:admin | SUDO | Debian 12 | 4C/8GB RAM     ║
║  [🍯 HONEYPOT] 45.33.2.19:22 | root:root | Fake Shell / Emulated           ║
╚════════════════════════════════════════════════════════════════════════════╝
 [Ctrl+C] Gracefully Stop | Results saved in output directory
```

---

## 📖 CLI Usage & Flags

```bash
Usage of phantom-ssh:
  -t, --targets string        Path to targets file (IP:PORT or IP, e.g. SSH.txt)
  -u, --users string          Path to usernames file, or a single username (e.g. root)
  -p, --passwords string      Path to passwords file, or a single password
  -C, --combos string         Path to combo file (user:pass or user pass)
  -w, --workers int           Number of concurrent worker threads (default 100)
      --timeout int           Connection and authentication timeout in seconds (default 3)
      --max-tries int         Max attempts per host to evade Fail2ban (default 2, 0 = unlim)
      --no-interleave         Disable /24 subnet interleaving
      --no-canary             Disable canary authentication trap detection
      --no-triage             Disable automated post-exploit hardware triage
      --jitter int            Max random jitter in milliseconds between probes
  -o, --output string         Output directory for results (default "./results")
      --no-tui                Disable TUI dashboard, print raw hits to stdout
      --quiet                 Quiet mode: suppress non-essential output
  -i, --interactive           Force interactive configuration wizard
  -v, --version               Display phantom-ssh version
```

---

## 🛠️ Tactical Workflow Examples

### 1. Direct Pipeline with `phantom-scan`
Scan millions of hosts for port 22 with `phantom-scan` and pipe directly into `phantom-ssh`:
```bash
# 1. High-speed network reconnaissance with phantom-scan (creates SSH.txt)
phantom-scan -t country_kr_ranges.txt -p 22 --quick-ssh

# 2. Precision credential spray with Fail2ban evasion & hardware triage
./phantom-ssh -t SSH.txt -u root -p passwords.txt -w 200 --max-tries 2
```

### 2. Combo File Spray
```bash
./phantom-ssh -t SSH.txt -C combos.txt -w 150 -o ./loot
```

### 3. Headless Scripting / CI / Pipe Mode
```bash
./phantom-ssh -t SSH.txt -C combos.txt --no-tui --quiet | grep -i "ROOT"
```

### 4. Interactive Wizard Mode
Launch with no arguments or `-i` to enter the guided wizard:
```bash
./phantom-ssh
```

---

## 🏗️ Compilation & Clean Builds

Zero developer path leaks or symbols are embedded in the output binaries (`-ldflags="-s -w" -trimpath`):

```bash
# Windows
build.bat

# Linux / macOS
chmod +x build.sh && ./build.sh
```
