#!/usr/bin/env python3
# ssh_cve_checker.py
# author: Eli V.
#
# started this after reading about CVE-2024-6387 (regreSSHion) and realizing
# that most of the risk is just a few config values sitting at defaults.
# expanded it to cover the other ssh CVEs that are config-dependent.
#
# checks sshd_config locally or on a remote target via ssh.
# can also auto-fix everything it finds.
#
# usage:
#   sudo python3 ssh_cve_checker.py -s                            scan local
#   sudo python3 ssh_cve_checker.py -f                            fix local
#   python3 ssh_cve_checker.py -p <ip> -u <user> -k <key> -s     scan remote
#   python3 ssh_cve_checker.py -p <ip> -u <user> --password -s   scan remote (password)
#   python3 ssh_cve_checker.py -p <ip> -u <user> -k <key> -f     fix remote
#   python3 ssh_cve_checker.py -p <ip> -u <user> -k <key> -P 2222 -s  custom port
#   python3 ssh_cve_checker.py -h

import argparse
import getpass
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime


try:
    import paramiko
except ImportError:
    print("[!] paramiko not found — needed for remote targets")
    print("    pip install paramiko")
    sys.exit(1)

# colors
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"

SSHD_CONFIG = "/etc/ssh/sshd_config"

# each check has:
#   id           - CVE id or "Best Practice"
#   description  - one liner
#   config_key   - the sshd_config key (lowercase)
#   safe_values  - values that are NOT vulnerable (None = handled in code)
#   default      - openssh default if key isn't set
#   fix_value    - what to write when fixing
#   severity     - CRITICAL / HIGH / MEDIUM / LOW
#   note         - shown in output under the result
#   version_range - (min, max) tuple as (major*100+minor) ints, None = always applies
#                   e.g. (805, 907) means 8.5p1 up to and including 9.7p1
#                   "Best Practice" checks have None — always relevant regardless of version
CHECKS = [
    {
        "id":            "CVE-2024-6387",
        "check_type":    "cve",
        "description":   "regreSSHion — pre-auth RCE via signal handler race condition",
        "config_key":    "logingracetime",
        "safe_values":   ["0"],
        "default":       "120",
        "fix_value":     "LoginGraceTime 0",
        "severity":      "CRITICAL",
        "note":          "affects openssh 8.5p1-9.7p1. setting LoginGraceTime=0 kills the race window.",
        "version_range": (805, 907),
    },
    {
        "id":            "CVE-2016-3115",
        "check_type":    "cve",
        "description":   "xauth command injection via X11 forwarding",
        "config_key":    "x11forwarding",
        "safe_values":   ["no"],
        "default":       "no",
        "fix_value":     "X11Forwarding no",
        "severity":      "HIGH",
        "note":          "affects openssh < 7.2p2. only exploitable if X11Forwarding is on.",
        "version_range": (0, 701),
    },
    {
        "id":            "CVE-2023-38408",
        "check_type":    "cve",
        "description":   "ssh-agent RCE via PKCS#11 over forwarded agent socket",
        "config_key":    "allowagentforwarding",
        "safe_values":   ["no"],
        "default":       "yes",
        "fix_value":     "AllowAgentForwarding no",
        "severity":      "HIGH",
        "note":          "affects openssh 5.5-9.3p1. needs agent forwarded to attacker box to trigger.",
        "version_range": (505, 903),
    },
    {
        "id":            "CVE-2025-26466",
        "check_type":    "cve",
        "description":   "pre-auth memory/CPU DoS via SSH2_MSG_PING",
        "config_key":    "persourcepenalties",
        "safe_values":   ["yes"],
        "default":       "no",
        "fix_value":     "PerSourcePenalties yes",
        "severity":      "HIGH",
        "note":          "affects openssh 9.5p1-9.9p1. PerSourcePenalties rate-limits abusive sources.",
        "version_range": (905, 909),
    },
    {
        "id":            "CVE-2015-6563",
        "check_type":    "cve",
        "description":   "PermitRootLogin logic error — may allow root password login",
        "config_key":    "permitrootlogin",
        "safe_values":   ["no", "prohibit-password", "without-password", "forced-commands-only"],
        "default":       "prohibit-password",
        "fix_value":     "PermitRootLogin no",
        "severity":      "HIGH",
        "note":          "affects openssh 7.0 only. PermitRootLogin yes is bad practice regardless.",
        "version_range": (700, 700),
    },
    {
        "id":            "Brute Force Risk",
        "check_type":    "hardening",
        "description":   "password authentication is on",
        "config_key":    "passwordauthentication",
        "safe_values":   ["no"],
        "default":       "yes",
        "fix_value":     "PasswordAuthentication no",
        "severity":      "MEDIUM",
        "note":          "open to password spray, credential stuffing, brute force. disable and use keys.",
        "version_range": None,
    },
    {
        "id":            "Account Takeover Risk",
        "check_type":    "hardening",
        "description":   "empty passwords allowed",
        "config_key":    "permitemptypasswords",
        "safe_values":   ["no"],
        "default":       "no",
        "fix_value":     "PermitEmptyPasswords no",
        "severity":      "CRITICAL",
        "note":          "any account with no password is freely accessible. no credentials needed.",
        "version_range": None,
    },
    {
        "id":            "Brute Force Risk",
        "check_type":    "hardening",
        "description":   "MaxAuthTries is too high",
        "config_key":    "maxauthtries",
        "safe_values":   None,
        "default":       "6",
        "fix_value":     "MaxAuthTries 3",
        "severity":      "LOW",
        "note":          "6 attempts per connection gives attackers room to try passwords. keep it at 3.",
        "version_range": None,
    },
]

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      YELLOW,
}


def banner():
    print(f"{BOLD}{'=' * 58}")
    print("   OpenSSH CVE Configuration Checker  //  by Eli V.")
    print(f"{'=' * 58}{NC}")
    print()


def need_root():
    if os.geteuid() != 0:
        print(f"{RED}[!] need root to read sshd_config locally{NC}")
        print(f"    run: sudo python3 {sys.argv[0]} -s")
        sys.exit(1)


def parse_config(raw: str) -> dict:
    # strip comments and blank lines, return lowercase key -> value
    out = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].lower()] = parts[1].strip()
    return out


def check_exploitable(chk: dict, config: dict) -> tuple[bool, str]:
    key = chk["config_key"]
    val = config.get(key, chk["default"]).lower()

    # maxauthtries is numeric — flag if > 3
    if key == "maxauthtries":
        try:
            return int(val) > 3, val
        except ValueError:
            return False, val

    safe = [v.lower() for v in chk["safe_values"]]
    return val not in safe, val


def show_result(chk: dict, status: str, val: str):
    sev   = chk["severity"]
    color = SEV_COLOR.get(sev, NC)

    if status == "safe":
        label = f"{GREEN}[+] SAFE{NC}"
    elif status == "vulnerable":
        label = f"{color}[!] VULNERABLE{NC}"
    elif status == "hardening":
        label = f"{YELLOW}[-] HARDENING{NC}"
    elif status == "suggestion":
        label = f"{CYAN}[~] SUGGESTION{NC}"
    else:
        label = f"{YELLOW}[?] UNKNOWN{NC}"

    print(f"  {label} {BOLD}{chk['id']}{NC} — {chk['description']}")
    print(f"             {DIM}{val}  |  {chk['note']}{NC}")
    print()


def run_checks(config: dict, ver_int: int | None) -> tuple[list[dict], list[dict], list[dict]]:
    # returns (vulnerable_list, hardening_list, suggestion_list)
    # vulnerable = cve check + bad config + version in affected range
    # hardening  = best-practice check + bad config
    # suggestion = cve check + bad config + version outside affected range
    vulnerable_list = []
    hardening_list  = []
    suggestion_list = []

    for chk in CHECKS:
        bad, val = check_exploitable(chk, config)
        chk["_val"] = val

        if not bad:
            show_result(chk, "safe", val)
            continue

        if chk["check_type"] == "hardening":
            show_result(chk, "hardening", val)
            hardening_list.append(chk)
            continue

        # cve check
        if version_in_range(ver_int, chk["version_range"]):
            show_result(chk, "vulnerable", val)
            vulnerable_list.append(chk)
        else:
            show_result(chk, "suggestion", val)
            suggestion_list.append(chk)

    return vulnerable_list, hardening_list, suggestion_list


def show_summary(vulnerable_list: list[dict], hardening_list: list[dict], suggestion_list: list[dict]):
    total      = len(CHECKS)
    vulnerable = len(vulnerable_list)
    hardening  = len(hardening_list)
    suggestions = len(suggestion_list)
    safe       = total - vulnerable - hardening - suggestions

    print(f"{BOLD}{'─' * 58}")
    print(f"  results         : {total} checks total")
    print(f"  {GREEN}safe            : {safe}{NC}")
    print(f"  {RED}vulnerable      : {vulnerable}  (CVE + version matches + bad config){NC}")
    print(f"  {YELLOW}hardening issues: {hardening}  (better for security + bad config){NC}")
    print(f"  {CYAN}suggestions     : {suggestions}  (CVE + version does not match + bad config){NC}")
    print(f"{'─' * 58}{NC}")
    print()

    if vulnerable_list:
        print(f"{BOLD}  vulnerable (will be fixed with -f):{NC}")
        for chk in vulnerable_list:
            color    = SEV_COLOR.get(chk["severity"], NC)
            cur_val  = chk.get("_val", chk["default"])
            fix      = chk["fix_value"]
            key_name = fix.split()[0]
            print(f"  {color}[{chk['severity']}]{NC} {chk['id']} — {chk['description']}")
            print(f"         current : {RED}{key_name} {cur_val}{NC}")
            print(f"         fix     : {GREEN}{fix}{NC}")
        print()

    if hardening_list:
        print(f"{BOLD}  hardening issues (will be fixed with -f):{NC}")
        for chk in hardening_list:
            color    = SEV_COLOR.get(chk["severity"], NC)
            cur_val  = chk.get("_val", chk["default"])
            fix      = chk["fix_value"]
            key_name = fix.split()[0]
            print(f"  {color}[{chk['severity']}]{NC} {chk['id']} — {chk['description']}")
            print(f"         current : {YELLOW}{key_name} {cur_val}{NC}")
            print(f"         fix     : {GREEN}{fix}{NC}")
        print()

    if suggestion_list:
        print(f"{BOLD}  suggestions (version not in affected range — -f won't touch these):{NC}")
        for chk in suggestion_list:
            cur_val  = chk.get("_val", chk["default"])
            fix      = chk["fix_value"]
            key_name = fix.split()[0]
            print(f"  {CYAN}[suggestion]{NC} {chk['id']} — {chk['description']}")
            print(f"         current : {YELLOW}{key_name} {cur_val}{NC}")
            print(f"         consider: {fix}")
        print()


# ── version helper ────────────────────────────────────────────────────────────

def get_local_version() -> str:
    try:
        r = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
        return (r.stderr or r.stdout).strip()
    except FileNotFoundError:
        return "not found"


def parse_version(ver: str) -> int | None:
    # returns major*100+minor as int, e.g. 9.2 -> 902, 10.2 -> 1002
    # returns None if unparseable
    m = re.search(r"OpenSSH[_\s](\d+)\.(\d+)p?", ver, re.IGNORECASE)
    if m:
        return int(m.group(1)) * 100 + int(m.group(2))
    return None


def version_in_range(ver_int: int | None, version_range: tuple | None) -> bool:
    # returns True if the version falls within the CVE's affected range.
    # if version_range is None (best practice) or version unknown, always returns True.
    if version_range is None or ver_int is None:
        return True
    lo, hi = version_range
    return lo <= ver_int <= hi


def show_version(ver: str) -> int | None:
    # prints version info and returns parsed int for use in checks
    ver_int = parse_version(ver)
    print(f"{CYAN}[i] openssh: {ver}{NC}")
    if ver_int is None:
        print(f"{YELLOW}[i] couldn't parse version — CVE range checks will be skipped{NC}")
    elif (ver_int >= 805) and (ver_int <= 907):
        print(f"{YELLOW}[i] version in CVE-2024-6387 vulnerable range — update to 9.8p1+{NC}")
    else:
        print(f"{GREEN}[i] version not in any known CVE range — config suggestions only{NC}")
    print()
    return ver_int


# ── local ─────────────────────────────────────────────────────────────────────

def read_local_config() -> str | None:
    if not os.path.isfile(SSHD_CONFIG):
        print(f"{RED}[!] sshd_config not found at {SSHD_CONFIG}{NC}")
        return None
    try:
        with open(SSHD_CONFIG) as f:
            return f.read()
    except PermissionError:
        print(f"{RED}[!] can't read {SSHD_CONFIG} — are you root?{NC}")
        return None


def scan_local():
    print(f"{BOLD}[~] target: local machine{NC}")
    print()
    ver_int = show_version(get_local_version())

    raw = read_local_config()
    if raw is None:
        sys.exit(1)

    config = parse_config(raw)
    vuln_list, hardening_list, sugg_list = run_checks(config, ver_int)
    show_summary(vuln_list, hardening_list, sugg_list)


# ── ssh connection ─────────────────────────────────────────────────────────────

def ssh_connect(ip: str, user: str, key: str | None, password: str | None, port: int = 22) -> paramiko.SSHClient | None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key:
            key = os.path.expanduser(key)
            if not os.path.isfile(key):
                print(f"{RED}[!] key not found: {key}{NC}")
                return None
            print(f"[*] connecting to {ip}:{port} as {user} (key: {key})")
            client.connect(ip, port=port, username=user, key_filename=key,timeout=10, look_for_keys=False, allow_agent=False)
        elif password:
            print(f"[*] connecting to {ip}:{port} as {user} (password)")
            client.connect(ip, port=port, username=user, password=password,timeout=10, look_for_keys=False, allow_agent=False)
        else:
            print(f"{RED}[!] no auth method — use -k or --password{NC}")
            return None

        print(f"{GREEN}[+] connected{NC}")
        return client

    except paramiko.AuthenticationException:
        print(f"{RED}[!] auth failed{NC}")
    except paramiko.SSHException as e:
        print(f"{RED}[!] ssh error: {e}{NC}")
    except TimeoutError:
        print(f"{RED}[!] timed out{NC}")
    except OSError as e:
        print(f"{RED}[!] network error: {e}{NC}")

    return None


def remote_cmd(client: paramiko.SSHClient, cmd: str) -> str | None:
    try:
        _, stdout, _ = client.exec_command(cmd)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        return out if out else None
    except paramiko.SSHException as e:
        print(f"{RED}[!] command failed: {e}{NC}")
        return None


def read_remote_config(client: paramiko.SSHClient, user: str) -> str | None:
    print(f"[*] reading remote {SSHD_CONFIG}...")
    raw = remote_cmd(client, f"cat {SSHD_CONFIG}")
    if not raw:
        print(f"{YELLOW}[~] retrying with sudo...{NC}")
        raw = remote_cmd(client, f"sudo cat {SSHD_CONFIG} 2>/dev/null")
    if not raw:
        print(f"{RED}[!] couldn't read remote sshd_config")
        print(f"    user '{user}' needs read access or passwordless sudo{NC}")
    return raw


# ── remote scan ───────────────────────────────────────────────────────────────

def scan_remote(ip: str, user: str, key: str | None, password: str | None, port: int = 22):
    print(f"{BOLD}[~] target: {ip}:{port}{NC}")
    print()

    client = ssh_connect(ip, user, key, password, port)
    if not client:
        sys.exit(1)

    print()

    try:
        ver = remote_cmd(client, "ssh -V 2>&1") or remote_cmd(client, "sshd -V 2>&1") or "unknown"
        ver_int = show_version(ver)

        raw = read_remote_config(client, user)
        if not raw:
            return

        config = parse_config(raw)
        vuln_list, hardening_list, sugg_list = run_checks(config, ver_int)
        show_summary(vuln_list, hardening_list, sugg_list)
    finally:
        client.close()


# ── fix helpers ───────────────────────────────────────────────────────────────

def build_fixed_config(raw: str, ver_int: int | None, force: bool = False) -> tuple[str, list[str]]:
    # fix only checks that are actually bad
    current_config = parse_config(raw)

    lines   = raw.splitlines(keepends=True)
    changes = []
    handled = set()
    fix_map = {}

    for chk in CHECKS:
        bad, _ = check_exploitable(chk, current_config)
        if not bad:
            continue

        check_type = chk.get("check_type", "cve")

        if check_type == "hardening":
            fix_map[chk["config_key"]] = chk["fix_value"]
        elif version_in_range(ver_int, chk["version_range"]) or force:
            fix_map[chk["config_key"]] = chk["fix_value"]

    out = []
    for line in lines:
        stripped = line.strip()

        if stripped.startswith("#") or not stripped:
            out.append(line)
            continue

        parts = stripped.split(None, 1)
        key   = parts[0].lower()

        if key in fix_map and key not in handled:
            new_line = fix_map[key] + "\n"

            if line.strip().lower() != fix_map[key].lower():
                changes.append(f"  changed: '{line.strip()}' -> '{fix_map[key]}'")
                out.append(new_line)
            else:
                out.append(line)

            handled.add(key)
        else:
            out.append(line)

    missing = []
    for key, fix_value in fix_map.items():
        if key not in handled:
            missing.append(fix_value)
            changes.append(f"  added: '{fix_value}'")

    if missing:
        out.append("\n# added by ssh_cve_checker.py (Eli V.)\n")
        for m in missing:
            out.append(m + "\n")

    return "".join(out), changes


def restart_sshd_local():
    print("[*] restarting sshd...")
    # kali/debian use 'ssh', rhel/arch use 'sshd'
    for svc in ["ssh", "sshd"]:
        r = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"{GREEN}[+] restarted (service: {svc}){NC}")
            return
    print(f"{RED}[!] couldn't restart — try manually:{NC}")
    print("    sudo systemctl restart ssh")
    print("    sudo systemctl restart sshd")


# ── local fix ─────────────────────────────────────────────────────────────────

def fix_local(force: bool = False):
    print(f"{BOLD}[~] mode: fix (local){NC}")

    if force:
        print(f"{YELLOW}[~] force mode enabled — suggestions will also be fixed{NC}")

    print()

    ver_int = parse_version(get_local_version())
    raw     = read_local_config()
    if raw is None:
        sys.exit(1)

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup  = f"{SSHD_CONFIG}.bak_{ts}"
    shutil.copy2(SSHD_CONFIG, backup)
    print(f"{GREEN}[+] backup: {backup}{NC}")
    print()

    new_raw, changes = build_fixed_config(raw, ver_int, force=force)

    if not changes:
        print(f"{GREEN}[+] nothing to fix — config looks good{NC}")
        return

    print(f"[*] making {len(changes)} change(s):")
    for c in changes:
        print(f"  {YELLOW}{c}{NC}")
    print()

    with open(SSHD_CONFIG, "w") as f:
        f.write(new_raw)
    print(f"{GREEN}[+] sshd_config updated{NC}")
    print()

    restart_sshd_local()
    print()

    # verify — only check things that apply to this version
    print("[*] verifying...")
    raw2 = read_local_config()
    if raw2:
        config    = parse_config(raw2)
        still_bad = []
        for chk in CHECKS:
            bad = check_exploitable(chk, config)[0]
            if not bad:
                continue
            check_type = chk.get("check_type", "cve")
            if check_type == "hardening":
                still_bad.append(chk)
            elif version_in_range(ver_int, chk["version_range"]) or force:
                still_bad.append(chk)
        if not still_bad:
            print(f"{GREEN}[+] all checks pass — good to go{NC}")
        else:
            print(f"{RED}[!] {len(still_bad)} check(s) still failing:{NC}")
            for chk in still_bad:
                print(f"    {chk['id']} -> {chk['fix_value']}")


# ── remote fix ────────────────────────────────────────────────────────────────

def fix_remote(ip: str, user: str, key: str | None, password: str | None, port: int = 22, force: bool = False):
    print(f"{BOLD}[~] mode: fix (remote: {ip}:{port}){NC}")

    if force:
        print(f"{YELLOW}[~] force mode enabled — suggestions will also be fixed{NC}")

    print()

    client = ssh_connect(ip, user, key, password, port)
    if not client:
        sys.exit(1)

    print()

    try:
        ver     = remote_cmd(client, "ssh -V 2>&1") or remote_cmd(client, "sshd -V 2>&1") or "unknown"
        ver_int = parse_version(ver)
        if ver_int:
            print(f"{CYAN}[i] remote openssh: {ver}{NC}")
        print()

        raw = read_remote_config(client, user)
        if not raw:
            return

        new_raw, changes = build_fixed_config(raw, ver_int, force=force)

        if not changes:
            print(f"{GREEN}[+] nothing to fix — config looks good{NC}")
            return

        print(f"[*] making {len(changes)} change(s):")
        for c in changes:
            print(f"  {YELLOW}{c}{NC}")
        print()

        # backup first
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup  = f"{SSHD_CONFIG}.bak_{ts}"
        remote_cmd(client, f"sudo cp {SSHD_CONFIG} {backup}")
        ok = remote_cmd(client, f"test -f {backup} && echo ok")
        if ok == "ok":
            print(f"{GREEN}[+] backup: {backup}{NC}")
        else:
            print(f"{RED}[!] couldn't create backup — aborting")
            print(f"    user '{user}' probably needs passwordless sudo{NC}")
            return

        # upload via sftp to /tmp then sudo mv into place
        tmp = f"/tmp/sshd_config_{ts}"
        sftp = client.open_sftp()
        try:
            with sftp.open(tmp, "w") as fh:
                fh.write(new_raw)
        finally:
            sftp.close()

        remote_cmd(client, f"sudo mv {tmp} {SSHD_CONFIG} && sudo chmod 644 {SSHD_CONFIG}")
        print(f"{GREEN}[+] sshd_config updated on {ip}{NC}")
        print()

        # restart remote sshd — try both names
        print("[*] restarting remote sshd...")
        out = remote_cmd(
            client,
            "sudo systemctl restart ssh 2>/dev/null || "
            "sudo systemctl restart sshd 2>/dev/null || "
            "sudo service ssh restart 2>/dev/null"
        )
        if out:
            print(f"{YELLOW}[~] {out}{NC}")
        else:
            print(f"{GREEN}[+] restarted{NC}")
        print()

        # verify
        print("[*] verifying...")
        raw2 = remote_cmd(client, f"sudo cat {SSHD_CONFIG}")
        if raw2:
            config    = parse_config(raw2)
            still_bad = []
            for chk in CHECKS:
                bad = check_exploitable(chk, config)[0]
                if not bad:
                    continue
                check_type = chk.get("check_type", "cve")
                if check_type == "hardening":
                    still_bad.append(chk)
                elif version_in_range(ver_int, chk["version_range"]) or force:
                    still_bad.append(chk)
            if not still_bad:
                print(f"{GREEN}[+] all checks pass on {ip}{NC}")
            else:
                print(f"{RED}[!] {len(still_bad)} still failing:{NC}")
                for chk in still_bad:
                    print(f"    {chk['id']} -> {chk['fix_value']}")
        else:
            print(f"{YELLOW}[~] couldn't verify — check {ip} manually{NC}")

    finally:
        client.close()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ssh_cve_checker.py",
        description=(
            "openssh CVE config checker  //  by Eli V.\n\n"
            "checks sshd_config for misconfigs tied to known CVEs.\n"
            "works locally or on remote targets over ssh.\n\n"
            "CVEs:\n"
            "  CVE-2024-6387  regreSSHion RCE       (LoginGraceTime)\n"
            "  CVE-2016-3115  xauth injection        (X11Forwarding)\n"
            "  CVE-2023-38408 ssh-agent RCE          (AllowAgentForwarding)\n"
            "  CVE-2025-26466 pre-auth DoS           (PerSourcePenalties)\n"
            "  CVE-2015-6563  root login logic       (PermitRootLogin)\n"
            "  Brute Force Risk  password auth          (PasswordAuthentication)\n"
            "  Account Takeover Risk  empty passwords        (PermitEmptyPasswords)\n"
            "  Brute Force Risk  max auth tries         (MaxAuthTries)\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    parser.add_argument("-h", "--help",     action="help",       help="show this and exit\n\n")
    parser.add_argument("-p", "--ip",       metavar="IP",        help="remote target IP\n\n")
    parser.add_argument("-u", "--user",     metavar="USER",      help="ssh username (needs sudo on remote)\n\n")
    parser.add_argument("-k", "--key",      metavar="KEY",       help="path to ssh private key\n\n")
    parser.add_argument("-P", "--port",     metavar="PORT",      help="ssh port (default: 22)\n\n", type=int, default=22)
    parser.add_argument("--password",       action="store_true", help="prompt for ssh password instead of key\n\n")
    parser.add_argument("-s", "--start",    action="store_true", help="start the scan (required to run)\n\n")
    parser.add_argument("-f", "--fix",      action="store_true", help="auto-fix everything found (backs up config first)\n\n")
    parser.add_argument("--force",          action="store_true", help="with -f, also fix suggestion-only CVE configs even if version is not in affected range\n\n")

    args = parser.parse_args()

    if args.force and not args.fix:
        print(f"{RED}[!] --force can only be used with -f{NC}")
        sys.exit(1)

    # no args → help + sudo reminder
    if len(sys.argv) == 1:
        parser.print_help()
        print()
        if os.geteuid() != 0:
            print(f"{RED}[!] sudo is required to run this tool{NC}")
            print(f"    try: sudo python3 {sys.argv[0]} -s")
        sys.exit(0)

    banner()

    if args.ip:
        if not args.user:
            print(f"{RED}[!] -u is required with -p{NC}")
            sys.exit(1)
        if not args.key and not args.password:
            print(f"{RED}[!] need -k or --password for auth{NC}")
            sys.exit(1)
        if not args.start and not args.fix:
            print(f"{RED}[!] add -s to scan or -f to fix{NC}")
            sys.exit(1)

        pw = getpass.getpass(f"password for {args.user}@{args.ip}: ") if args.password else None

        if args.fix:
            fix_remote(args.ip, args.user, args.key, pw, args.port, force=args.force)
        else:
            scan_remote(args.ip, args.user, args.key, pw, args.port)
    else:
        need_root()
        if not args.start and not args.fix:
            parser.print_help()
            sys.exit(0)
        if args.fix:
            fix_local(force=args.force)
        else:
            scan_local()

    print()
    print(f"{BOLD}{'=' * 58}{NC}")


if __name__ == "__main__":
    main()