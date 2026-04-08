# ssh cve checker

A Python tool for checking OpenSSH configurations against known CVEs and real attack vectors. Supports local and remote targets, and can auto-fix everything it finds.

Started this after digging into CVE-2024-6387 (regreSSHion) and noticing that most of the risk comes down to a few config values sitting at their defaults on basically every fresh install. Expanded it to cover the other SSH CVEs that are config-dependent while I was at it.

---

## What it checks

The tool separates results into three categories:

- **Vulnerable** — bad config value AND the detected version falls within the CVE's affected range. `-f` will fix these.
- **Hardening issue** — best-practice config issue not tied to a specific vulnerable version. `-f` will fix these too.
- **Suggestion** — bad config value BUT the version is outside the affected range. Shown for awareness. `-f` will not touch these unless `--force` is used.

| ID | Description | Config key | Affected versions |
|----|-------------|------------|-------------------|
| CVE-2024-6387 | regreSSHion — pre-auth RCE via signal handler race condition | `LoginGraceTime` | 8.5p1 – 9.7p1 |
| CVE-2016-3115 | xauth command injection via X11 forwarding | `X11Forwarding` | < 7.2p2 |
| CVE-2023-38408 | ssh-agent RCE via PKCS#11 over forwarded agent socket | `AllowAgentForwarding` | 5.5 – 9.3p1 |
| CVE-2025-26466 | Pre-auth memory/CPU DoS via SSH2_MSG_PING | `PerSourcePenalties` | 9.5p1 – 9.9p1 |
| CVE-2015-6563 | PermitRootLogin logic error allowing root password auth | `PermitRootLogin` | 7.0 only |
| Brute Force Risk | Password authentication enabled | `PasswordAuthentication` | all versions |
| Account Takeover Risk | Empty passwords permitted | `PermitEmptyPasswords` | all versions |
| Brute Force Risk | MaxAuthTries too high (> 3) | `MaxAuthTries` | all versions |

A note on how checks work — if a directive isn't set in the config at all, the tool evaluates it against OpenSSH's compiled-in default rather than skipping it. So a box where everything is commented out still gets a real verdict. Commented lines like `#LoginGraceTime 2m` are ignored the same way OpenSSH ignores them.

---

## Requirements

- Python 3.10+
- `paramiko` — only needed for remote targets

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# no args → shows help + sudo warning if not root
python3 ssh_cve_checker.py

# scan local machine
sudo python3 ssh_cve_checker.py -s

# fix local machine (backs up config first, restarts sshd)
sudo python3 ssh_cve_checker.py -f

# fix local machine and also apply suggestion-only fixes
sudo python3 ssh_cve_checker.py -f --force

# scan remote via SSH key
python3 ssh_cve_checker.py -p 192.168.1.10 -u root -k ~/.ssh/id_rsa -s

# scan remote via password
python3 ssh_cve_checker.py -p 192.168.1.10 -u root --password -s

# fix remote
python3 ssh_cve_checker.py -p 192.168.1.10 -u root -k ~/.ssh/id_rsa -f

# fix remote and also apply suggestion-only fixes
python3 ssh_cve_checker.py -p 192.168.1.10 -u root -k ~/.ssh/id_rsa -f --force

# non-standard port
python3 ssh_cve_checker.py -p 192.168.1.10 -u root -k ~/.ssh/id_rsa -P 2222 -s
```

---

## Flags

| Flag | Description |
|------|-------------|
| `-s` / `--start` | Start the scan — required, prevents accidental execution |
| `-f` / `--fix` | Auto-fix confirmed vulnerabilities and hardening issues in sshd_config |
| `--force` | Used with `-f` to also apply suggestion-only fixes even when the OpenSSH version is outside the affected CVE range |
| `-p` / `--ip` | Remote target IP |
| `-u` / `--user` | SSH username (needs root or passwordless sudo on remote) |
| `-k` / `--key` | Path to SSH private key |
| `-P` / `--port` | SSH port (default: 22) |
| `--password` | Prompt for SSH password instead of key |
| `-h` / `--help` | Show help |

---

## Auto-fix behavior

When `-f` is used the tool:

1. Detects the OpenSSH version first
2. Creates a timestamped backup (`sshd_config.bak_YYYYMMDD_HHMMSS`) before touching anything
3. Fixes:
   - confirmed vulnerabilities
   - hardening issues
   - suggestion-only findings only if `--force` is used

`--force` is useful if you want to harden the SSH config even when the installed OpenSSH version is not directly affected by a specific CVE.

> [!WARNING]
> `--force` may disable features such as X11 forwarding or agent forwarding even when the current OpenSSH version is not vulnerable. Use it when you want the most hardened configuration rather than the minimum required fix.

4. Replaces existing values in place, or appends at the bottom if the directive is missing entirely
5. Restarts sshd (tries both `ssh` and `sshd` service names — handles Kali/Debian vs RHEL/Arch)
6. Re-reads the config after restart to verify the changes took effect

For remote targets it uploads the patched config via SFTP to `/tmp`, then `sudo mv`s it into place — avoids shell redirection permission issues. The remote user needs passwordless sudo for `cp`, `mv`, `chmod`, and `systemctl`.

---

## Example output

```
==========================================================
   OpenSSH CVE Configuration Checker  //  by Eli V.
==========================================================

[~] target: local machine

[i] openssh: OpenSSH_9.2p1 Debian-2+deb12u7
[i] version in CVE-2024-6387 vulnerable range — update to 9.8p1+

  [!] VULNERABLE  CVE-2024-6387 — regreSSHion — pre-auth RCE via signal handler race condition
            120  |  affects openssh 8.5p1-9.7p1. setting LoginGraceTime=0 kills the race window.

  [~] SUGGESTION  CVE-2016-3115 — xauth command injection via X11 forwarding
            yes  |  affects openssh < 7.2p2. only exploitable if X11Forwarding is on.

  [!] VULNERABLE  Brute Force Risk — password authentication is on
            yes  |  open to password spray, credential stuffing, brute force. disable and use keys.

  [+] SAFE        Account Takeover Risk — empty passwords allowed
            no   |  any account with no password is freely accessible. no credentials needed.

──────────────────────────────────────────────────────────
  results         : 8 checks total
  safe            : 2
  vulnerable      : 1  (CVE + version matches + bad config)
  hardening issues: 2  (better for security + bad config)
  suggestions     : 3  (CVE + version does not match + bad config)
──────────────────────────────────────────────────────────

  vulnerable (will be fixed with -f):
  [CRITICAL] CVE-2024-6387 — regreSSHion — pre-auth RCE via signal handler race condition
         current : LoginGraceTime 120
         fix     : LoginGraceTime 0

  suggestions (version not in affected range — -f won't touch these):
  [suggestion] CVE-2016-3115 — xauth command injection via X11 forwarding
         current : X11Forwarding yes
         consider: X11Forwarding no
```

---

## Notes

- `-s` is required to run a scan — avoids accidentally scanning when you just meant to check flags.
- Version detection drives what counts as vulnerable vs suggestion. If the version cannot be parsed, CVE checks are treated as potentially applicable and will be shown as vulnerable if the related config value is unsafe.
- The version check for CVEs is separate from the config check — a patched version with a bad config still gets flagged as a suggestion worth fixing, and a vulnerable version with the right config value is marked safe for that specific CVE.
- Remote scans read the actual `sshd_config` over SSH, not just the banner — real config-based verdict, not a guess from the version string.
- The remote fix requires passwordless sudo on the target. If that's not available, run the scan first and apply the fixes manually.

---

## Disclaimer

Only use this on systems you own or have explicit written permission to test.

---

## References

**CVE-2024-6387 — regreSSHion**
- [Qualys advisory](https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt)
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**CVE-2016-3115 — xauth injection**
- [OpenSSH security page](https://www.openssh.com/security.html)
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2016-3115)
- [Exploit-DB PoC](https://www.exploit-db.com/exploits/39569)

**CVE-2023-38408 — ssh-agent RCE**
- [Qualys advisory](https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt)
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-38408)
- [OpenSSH 9.3p2 release notes](https://www.openssh.com/txt/release-9.3p2)

**CVE-2025-26466 — pre-auth DoS**
- [Qualys advisory](https://www.qualys.com/2025/02/18/openssh-vulnerabilities.txt)
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-26466)
- [OpenSSH 9.9p2 release notes](https://www.openssh.com/txt/release-9.9p2)

**CVE-2015-6563 — PermitRootLogin logic**
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-6563)
- [OpenSSH 7.1 release notes](https://www.openssh.com/txt/release-7.1)

**General**
- [OpenSSH full security history](https://www.openssh.com/security.html)
- [sshd_config man page](https://man.openbsd.org/sshd_config)