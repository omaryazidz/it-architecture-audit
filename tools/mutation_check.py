"""Uji mutasi: rusak kode satu per satu di salinan; setiap kerusakan harus membuat minimal satu tes gagal.
Jalankan: python tools/mutation_check.py"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SRC = pathlib.Path(__file__).resolve().parent.parent
MUTATIONS = {
    "aturan SSH root dibalik": ("audit/rules.py", 'not in ("no", "prohibit-password", "without-password")', 'in ("no", "prohibit-password", "without-password")'),
    "firewall selalu dianggap mati": ("audit/rules.py", 'return fw["ufw_active"] or fw["firewalld_active"] or fw["nft_rules"] > 5', "return False"),
    "batas disk 85% jadi 100%": ("audit/rules.py", 'd["used_pct"] >= 85', 'd["used_pct"] >= 100'),
    "backup usang tidak terdeteksi": ("audit/rules.py", "age is None or age > 2", "age is None"),
    "EOL tidak pernah terdeteksi": ("audit/rules.py", "if d < today:", "if False:"),
    "SEC-15 ikut memicu saat file bisa diunduh": ("audit/rules.py", 'and not f["web"]["sensitive_downloadable"] else None', "else None"),
    "bobot indeks Tinggi 10 jadi 1": ("audit/report.py", 'PENALTY = {"Tinggi": 10,', 'PENALTY = {"Tinggi": 1,'),
    "audit ulang menganggap semua selesai": ("audit/report.py", 'if f["id"] not in a_ids]', "if True]"),
    "HTML tidak di-escape": ("audit/report.py", "e = html.escape\n    c = r[\"counts\"]\n    out = [f\"<!doctype", "e = str\n    c = r[\"counts\"]\n    out = [f\"<!doctype"),
    "alamat loopback dianggap publik": ("collect.py", "public = not ipaddress.ip_address(addr).is_loopback", "public = True"),
    "job dpkg dihitung sebagai backup": ("collect.py", "if any(s in base for s in SYSTEM_JOBS):", "if False:"),
    "akhiran %interface tidak dibuang": ("collect.py", 'addr = addr.strip("[]").split("%")[0]', 'addr = addr.strip("[]")'),
}
for name, (fname, old, new) in MUTATIONS.items():
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(SRC, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", ".git", ".venv", "results"))
        f = pathlib.Path(d, fname)
        t = f.read_text(encoding="utf-8")
        assert old in t, f"pola tidak ketemu: {name}"
        f.write_text(t.replace(old, new, 1), encoding="utf-8")
        res = subprocess.run([sys.executable, "run_tests.py"], cwd=d, capture_output=True, text=True,
                             encoding="utf-8", timeout=120)
        failed = len(re.findall(r"\[(FAIL|ERROR)\]", res.stdout)) or int(res.returncode != 0)
        print(f"{'TERTANGKAP' if failed else 'LOLOS (tes lemah!)':20} {name}  ({failed} tes gagal)")
