#!/usr/bin/env python3
"""Kolektor fakta server Linux untuk audit arsitektur. HANYA MEMBACA: tidak mengubah apa pun.

    sudo python3 collect.py > facts.json

Yang dikumpulkan: versi OS, pembaruan, port yang terbuka, firewall, SSH, akun, layanan, web server,
sertifikat TLS, database, backup, monitoring. Isi file rahasia TIDAK dibaca: untuk /etc/shadow hanya dicek
apakah kolom password kosong, dan untuk webroot hanya NAMA file sensitif yang dilaporkan.
"""
import datetime as dt
import glob
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys

SENSITIVE_NAMES = (".env", ".git", "backup.sql", "dump.sql", "db.sql", "wp-config.php.bak", "id_rsa", ".htpasswd")
SENSITIVE_EXT = (".sql", ".bak", ".old", ".orig", ".swp")
RISKY_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
               11211: "Memcached", 2375: "Docker API (tanpa TLS)", 5900: "VNC", 3389: "RDP", 23: "Telnet", 21: "FTP"}
MONITOR_AGENTS = ("node_exporter", "prometheus-node-exporter", "zabbix-agent", "zabbix-agent2", "netdata",
                  "datadog-agent", "newrelic-infra", "telegraf", "amazon-cloudwatch-agent", "nrpe", "snmpd")
SYSTEM_JOBS = ("dpkg", "apt", "logrotate", "man-db", "mdadm", "e2scrub", "fstrim", "update-notifier", "motd",
               "sysstat", "passwd", "popularity", "cracklib", "apport", "ubuntu-advantage", "ua-timer")
BACKUP_WORDS = ("backup", "pg_dump", "mysqldump", "restic", "borg", "rsnapshot", "duplicity", "rclone", "pg-backup")


def run(cmd, timeout=20):
    """Jalankan perintah, kembalikan stdout (string kosong bila gagal). Tidak pernah melempar error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read(path, limit=200_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def parse_ss(text):
    """Parse keluaran `ss -tulnpH` menjadi daftar {proto, address, port, public, process}."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        proto, local = p[0], p[4]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = re.search(r'\("([^"]+)"', line)
        addr = addr.strip("[]").split("%")[0]  # "127.0.0.53%lo" -> "127.0.0.53"
        try:
            public = not ipaddress.ip_address(addr).is_loopback
        except ValueError:  # "*" dan bentuk wildcard lain = semua interface
            public = True
        out.append({"proto": proto, "address": addr, "port": int(port), "public": public,
                    "process": proc.group(1) if proc else ""})
    return out


def parse_df(text):
    rows = []
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) >= 6 and p[4].endswith("%") and p[0].startswith("/"):
            rows.append({"mount": p[5], "used_pct": int(p[4][:-1]), "size_gb": round(int(p[1]) / 1048576, 1)})
    return rows


def system():
    os_rel = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release"), re.M))
    up = float(read("/proc/uptime").split()[0]) if read("/proc/uptime") else 0
    mem = int(re.search(r"MemTotal:\s+(\d+)", read("/proc/meminfo")).group(1)) // 1024
    return {
        "hostname": socket.gethostname(), "os": os_rel.get("PRETTY_NAME", ""), "os_id": os_rel.get("ID", ""),
        "os_version": os_rel.get("VERSION_ID", ""), "kernel": run(["uname", "-r"]).strip(),
        "uptime_days": round(up / 86400, 1), "cpus": os.cpu_count(), "memory_mb": mem,
        "virtualization": run(["systemd-detect-virt"]).strip() or "none",
        "disks": parse_df(run(["df", "-P", "-k"])), "swap_mb": int(re.search(r"SwapTotal:\s+(\d+)", read("/proc/meminfo")).group(1)) // 1024,
        "time_synced": "yes" in run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).lower(),
        "timezone": run(["timedatectl", "show", "-p", "Timezone", "--value"]).strip(),
    }


def updates():
    out = run("apt list --upgradable 2>/dev/null")
    lines = [l for l in out.splitlines() if "/" in l and "upgradable" in l]
    return {
        "pending": len(lines), "security_pending": sum(1 for l in lines if "-security" in l),
        "reboot_required": os.path.exists("/var/run/reboot-required"),
        "auto_updates": os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades") and
                        'Unattended-Upgrade "1"' in read("/etc/apt/apt.conf.d/20auto-upgrades"),
    }


def network():
    listening = parse_ss(run(["ss", "-tulnpH"]))
    ufw = run(["ufw", "status"])
    fw_cmd = run("nft list ruleset 2>/dev/null | grep -c 'rule\\|accept\\|drop'").strip()
    return {
        "listening": listening,
        "firewall": {"ufw_active": "Status: active" in ufw, "firewalld_active": run(["systemctl", "is-active", "firewalld"]).strip() == "active",
                     "nft_rules": int(fw_cmd) if fw_cmd.isdigit() else 0},
        "fail2ban": run(["systemctl", "is-active", "fail2ban"]).strip() == "active",
    }


def ssh():
    t = run(["sshd", "-T"])
    d = dict(l.split(None, 1) for l in t.splitlines() if " " in l)
    return {"present": bool(t), "port": d.get("port", "22"), "permitrootlogin": d.get("permitrootlogin", "?"),
            "passwordauthentication": d.get("passwordauthentication", "?"), "maxauthtries": d.get("maxauthtries", "?"),
            "x11forwarding": d.get("x11forwarding", "?")}


def accounts():
    passwd = [l.split(":") for l in read("/etc/passwd").splitlines() if l.count(":") >= 6]
    shadow = {l.split(":")[0]: l.split(":")[1] for l in read("/etc/shadow").splitlines() if l.count(":") >= 2}
    nologin = ("nologin", "false", "sync")
    login = [p[0] for p in passwd if not p[6].strip().endswith(nologin) and (int(p[2]) >= 1000 or p[2] == "0")]
    sudoers = set()
    for g in ("sudo", "wheel", "admin"):
        grp = run(["getent", "group", g]).strip().split(":")
        if len(grp) == 4 and grp[3]:
            sudoers.update(grp[3].split(","))
    return {
        "login_users": login, "sudo_users": sorted(sudoers),
        "extra_uid0": [p[0] for p in passwd if p[2] == "0" and p[0] != "root"],
        "empty_password": [u for u in login if shadow.get(u, "x") == ""],
        "keys": {u: os.path.exists(f"/home/{u}/.ssh/authorized_keys") and os.path.getsize(f"/home/{u}/.ssh/authorized_keys") > 0
                 for u in login if u != "root"},
    }


def services():
    units = run("systemctl list-units --type=service --state=running --no-legend --plain").splitlines()
    running = sorted(u.split()[0].removesuffix(".service") for u in units if u.strip())
    failed = [l.split()[0] for l in run("systemctl list-units --state=failed --no-legend --plain").splitlines() if l.strip()]
    return {"running": running, "failed": failed}


def curl(args, timeout=8):
    return run(["curl", "-sk", "-m", str(timeout), *args], timeout=timeout + 3)


def http_code(url):
    return curl(["-o", "/dev/null", "-w", "%{http_code}", url]).strip()


def probe_tls(port=443):
    """Protokol TLS usang yang BENAR-BENAR diterima server (handshake sungguhan, bukan membaca konfigurasi)."""
    accepted = []
    for proto in ("tls1", "tls1_1"):
        out = run(f"openssl s_client -connect 127.0.0.1:{port} -{proto} -cipher 'DEFAULT:@SECLEVEL=0' </dev/null 2>&1")
        if "BEGIN CERTIFICATE" in out:
            accepted.append(proto)
    return accepted


def web(listening):
    """Pemeriksaan web: konfigurasi (komentar diabaikan) ditambah uji langsung ke server lokal."""
    raw = run(["nginx", "-T"]) if shutil.which("nginx") else ""
    cfg = "\n".join(re.sub(r"#.*", "", l) for l in raw.splitlines())  # baris yang di-comment bukan konfigurasi aktif
    apache = shutil.which("apache2") or shutil.which("httpd")
    ports = {p["port"] for p in listening if p["proto"] == "tcp"}
    out = {"nginx": bool(cfg), "apache": bool(apache), "waf": "modsecurity on" in cfg, "autoindex_on": bool(re.search(r"autoindex\s+on", cfg)),
           "roots": sorted({m.strip() for m in re.findall(r"^\s*root\s+([^;]+);", cfg, re.M)}), "ssl_protocols":
           sorted(set(sum((p.split() for p in re.findall(r"ssl_protocols\s+([^;]+);", cfg)), []))),
           "server_version_exposed": False, "security_headers": [], "legacy_tls": [], "http_redirect": False,
           "sensitive_files": [], "sensitive_downloadable": [], "certs": []}
    if not (out["nginx"] or out["apache"]):
        return out

    base = "https://127.0.0.1" if 443 in ports else "http://127.0.0.1" if 80 in ports else None
    if base:
        head = curl(["-I", base + "/"])
        out["server_version_exposed"] = bool(re.search(r"(?im)^server:\s*\S+/\d", head))
        want = ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy")
        out["security_headers"] = [h for h in want if re.search(rf"(?im)^{h}:", head)]
    if 443 in ports:
        out["legacy_tls"] = probe_tls()
    if 80 in ports:
        r = curl(["-I", "http://127.0.0.1/"])
        out["http_redirect"] = bool(re.search(r"(?i)^HTTP/\S+\s+30[12]", r) and re.search(r"(?im)^location:\s*https://", r))

    for r in out["roots"]:
        for dirpath, dirs, files in os.walk(r):
            if dirpath[len(r):].count(os.sep) > 2:
                dirs[:] = []
                continue
            for n in list(dirs) + files:
                if n in SENSITIVE_NAMES or n.endswith(SENSITIVE_EXT):
                    out["sensitive_files"].append(os.path.join(dirpath, n))
    out["sensitive_files"] = out["sensitive_files"][:20]
    for path in out["sensitive_files"]:  # uji: apakah file itu benar-benar bisa diunduh lewat web server? (isi tidak dibaca)
        root = next(r for r in out["roots"] if path.startswith(r))
        rel = path[len(root):].replace(os.sep, "/")
        rel = rel + "/config" if rel.endswith("/.git") else rel
        if base and http_code(base + rel) in ("200", "206"):
            out["sensitive_downloadable"].append(path)

    for c in sorted(set(re.findall(r"ssl_certificate\s+([^;]+);", cfg))):
        end = run(["openssl", "x509", "-enddate", "-noout", "-in", c.strip()]).strip()
        subj = run(["openssl", "x509", "-subject", "-issuer", "-noout", "-in", c.strip()])
        if "notAfter=" in end:
            exp = dt.datetime.strptime(end.split("=")[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            s, i = (re.search(r"subject=(.*)", subj), re.search(r"issuer=(.*)", subj))
            out["certs"].append({"path": c.strip(), "days_left": (exp - dt.datetime.now(dt.timezone.utc)).days,
                                 "self_signed": bool(s and i and s.group(1).strip() == i.group(1).strip())})
    return out


def database():
    out = {}
    for name, pat in (("postgresql", "postgres"), ("mysql", "mysql|mariadb")):
        procs = run("ps -eo comm").split()
        out[name] = any(re.fullmatch(pat, p) or re.match(pat, p) for p in procs)
    return out


def is_backup_job(name, content=""):
    """True bila job terlihat sebagai backup DATA. Job bawaan paket sistem (dpkg-db-backup, dll) diabaikan."""
    base = os.path.basename(name).lower()
    if any(s in base for s in SYSTEM_JOBS):
        return False
    return any(w in base or w in content.lower() for w in BACKUP_WORDS)


def backup():
    hits = []
    for src in glob.glob("/etc/cron.*/*") + glob.glob("/etc/cron.d/*") + glob.glob("/var/spool/cron/crontabs/*"):
        if is_backup_job(src, read(src, 20000)):
            hits.append(src)
    timers = [u for l in run("systemctl list-timers --all --no-legend --plain").splitlines()
              for u in l.split() if u.endswith(".timer") and is_backup_job(u)]
    newest = None
    for d in ("/var/backups", "/backup", "/backups", "/var/backups/pg", "/srv/backup"):
        for dirpath, _, files in os.walk(d):
            if dirpath == "/var/backups":
                continue  # berkas langsung di sini = salinan sistem (passwd.bak, dpkg.status.*), bukan backup data
            for f in files:
                try:
                    m = os.path.getmtime(os.path.join(dirpath, f))
                    newest = max(newest or m, m)
                except OSError:
                    pass
    return {"scheduled_jobs": hits + timers, "newest_backup_age_days":
            round((dt.datetime.now().timestamp() - newest) / 86400, 1) if newest else None}


def containers():
    if not shutil.which("docker"):
        return {"docker": False}
    ps = run(["docker", "ps", "-q"]).split()
    return {"docker": True, "running": len(ps), "privileged": sum(1 for c in ps if "true" in run(
        ["docker", "inspect", "-f", "{{.HostConfig.Privileged}}", c]))}


def monitoring(running):
    agents = [a for a in MONITOR_AGENTS if any(a in s for s in running)]
    return {"agents": agents, "journal_persistent": os.path.isdir("/var/log/journal"),
            "logrotate": os.path.exists("/etc/logrotate.conf")}


def main():
    if os.geteuid() != 0:
        sys.exit("Jalankan sebagai root (sudo) agar semua fakta terbaca.")
    svc = services()
    net = network()
    facts = {"collected_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "collector": "collect.py/1.0", "system": system(), "updates": updates(), "network": net,
             "ssh": ssh(), "accounts": accounts(), "services": svc, "web": web(net["listening"]), "database": database(),
             "backup": backup(), "containers": containers(), "monitoring": monitoring(svc["running"])}
    json.dump(facts, sys.stdout, indent=2, ensure_ascii=False)
    print()


if __name__ == "__main__":
    main()
