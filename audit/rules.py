"""Aturan audit: tiap aturan memeriksa fakta dari collect.py dan mengembalikan bukti kalau ada masalah."""
import datetime as dt
from dataclasses import dataclass
from typing import Callable

SEVERITIES = ("Tinggi", "Sedang", "Rendah")

# Perkiraan akhir dukungan standar vendor. Verifikasi ke situs vendor sebelum dijadikan dasar keputusan.
EOL = {
    ("ubuntu", "18.04"): dt.date(2023, 5, 31), ("ubuntu", "20.04"): dt.date(2025, 5, 31),
    ("ubuntu", "22.04"): dt.date(2027, 6, 1), ("ubuntu", "24.04"): dt.date(2029, 5, 31),
    ("debian", "10"): dt.date(2024, 6, 30), ("debian", "11"): dt.date(2026, 8, 31),
    ("debian", "12"): dt.date(2028, 6, 30),
}
RISKY_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
               11211: "Memcached", 2375: "Docker API", 5900: "VNC", 3389: "RDP", 23: "Telnet", 21: "FTP"}


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    check: Callable[[dict], str | None]  # None = tidak ada masalah; string = bukti
    impact: str
    fix: str
    hours: float
    good: str
    applies: Callable[[dict], bool] = lambda f: True


def public_ports(f):
    return sorted({p["port"] for p in f["network"]["listening"] if p["public"] and p["proto"] == "tcp"})


def has_firewall(f):
    fw = f["network"]["firewall"]
    return fw["ufw_active"] or fw["firewalld_active"] or fw["nft_rules"] > 5


def _risky(f):
    hits = [f"{RISKY_PORTS[p['port']]} (:{p['port']}) terbuka di {p['address']}"
            for p in f["network"]["listening"] if p["public"] and p["proto"] == "tcp" and p["port"] in RISKY_PORTS]
    return "; ".join(hits) or None


def _eol(f, today=None):
    s = f["system"]
    d = EOL.get((s["os_id"], s["os_version"]))
    if not d:
        return None
    today = today or dt.date.today()
    if d < today:
        return f"{s['os']} sudah melewati akhir dukungan standar ({d.isoformat()})"
    if (d - today).days < 365:
        return f"{s['os']} berakhir dukungannya {d.isoformat()} (kurang dari 12 bulan lagi)"
    return None


def _disk(f):
    full = [f"{d['mount']} {d['used_pct']}%" for d in f["system"]["disks"] if d["used_pct"] >= 85]
    return ", ".join(full) or None


def _cert(f):
    bad = []
    for c in f["web"]["certs"]:
        if c["days_left"] < 30:
            bad.append(f"{c['path']} sisa {c['days_left']} hari")
        if c["self_signed"]:
            bad.append(f"{c['path']} self-signed (browser pengunjung akan menampilkan peringatan)")
    return "; ".join(bad) or None


def _backup(f):
    b = f["backup"]
    if not b["scheduled_jobs"]:
        return "tidak ditemukan cron/timer backup (kata kunci: backup, dump, restic, borg, rclone, dll)"
    return None


def _backup_stale(f):
    age = f["backup"]["newest_backup_age_days"]
    if f["backup"]["scheduled_jobs"] and (age is None or age > 2):
        return "jadwal backup ada, tapi " + ("tidak ada berkas backup ditemukan" if age is None else f"berkas terbaru berumur {age} hari")
    return None


def _spof(f):
    web = f["web"]["nginx"] or f["web"]["apache"]
    db = f["database"]["postgresql"] or f["database"]["mysql"]
    if web and db:
        return "web server dan database berjalan di server yang sama: satu server mati berarti semuanya mati"
    return None


R = Rule
RULES = [
    R("SEC-01", "Login SSH sebagai root diizinkan", "Tinggi", "Keamanan",
      lambda f: f"PermitRootLogin = {f['ssh']['permitrootlogin']}" if f["ssh"]["permitrootlogin"] not in ("no", "prohibit-password", "without-password") else None,
      "Penyerang tinggal menebak password satu akun yang namanya sudah pasti diketahui.",
      "Matikan login root dan pakai akun admin biasa dengan sudo.", 0.5,
      "Login SSH root ditolak.", lambda f: f["ssh"]["present"]),
    R("SEC-02", "Login SSH memakai password", "Tinggi", "Keamanan",
      lambda f: "PasswordAuthentication = yes" if f["ssh"]["passwordauthentication"] == "yes" else None,
      "Server bisa diserang brute force 24 jam sehari oleh bot di internet.",
      "Pindah ke SSH key, pastikan semua admin punya key, lalu matikan login password.", 1,
      "Login SSH hanya dengan key.", lambda f: f["ssh"]["present"]),
    R("SEC-03", "Tidak ada firewall aktif", "Tinggi", "Keamanan",
      lambda f: f"firewall tidak aktif; port TCP terbuka ke publik: {', '.join(map(str, public_ports(f)))}" if not has_firewall(f) else None,
      "Setiap layanan yang kebetulan berjalan langsung terpapar ke internet.",
      "Aktifkan firewall dengan kebijakan default tolak, buka hanya port yang dibutuhkan.", 1,
      "Firewall aktif.", lambda f: bool(public_ports(f))),
    R("SEC-04", "Layanan sensitif terbuka ke publik", "Tinggi", "Keamanan", _risky,
      "Database atau layanan internal yang terbuka sering dibobol lewat password lemah atau celah bawaan.",
      "Ikat layanan ke localhost atau jaringan privat, dan izinkan hanya server aplikasi lewat firewall.", 1,
      "Tidak ada database/layanan internal yang terbuka ke publik."),
    R("SEC-05", "File sensitif bisa diunduh lewat web server", "Tinggi", "Keamanan",
      lambda f: "terunduh (HTTP 200): " + ", ".join(f["web"]["sensitive_downloadable"][:6]) if f["web"]["sensitive_downloadable"] else None,
      "File seperti .env, .git, atau dump database membuka password dan seluruh kode sumber kepada siapa saja.",
      "Pindahkan file ke luar webroot dan blokir dotfile serta ekstensi sensitif di web server.", 0.5,
      "Tidak ada file sensitif yang bisa diunduh lewat web server.", lambda f: f["web"]["nginx"] or f["web"]["apache"]),
    R("SEC-15", "File sensitif masih tersimpan di webroot", "Rendah", "Keamanan",
      lambda f: ("tersimpan tapi diblokir web server: " + ", ".join(f["web"]["sensitive_files"][:6]))
      if f["web"]["sensitive_files"] and not f["web"]["sensitive_downloadable"] else None,
      "Sekarang diblokir, tapi satu kesalahan konfigurasi atau pembaruan web server bisa membukanya lagi.",
      "Pindahkan file ke luar webroot. Blokir di web server hanya sebagai lapisan kedua.", 0.5,
      "Webroot bersih dari file sensitif.", lambda f: f["web"]["nginx"] or f["web"]["apache"]),
    R("SEC-06", "Akun tanpa password atau UID 0 ganda", "Tinggi", "Keamanan",
      lambda f: "; ".join(x for x in (f"tanpa password: {', '.join(f['accounts']['empty_password'])}" if f["accounts"]["empty_password"] else "",
                                       f"UID 0 selain root: {', '.join(f['accounts']['extra_uid0'])}" if f["accounts"]["extra_uid0"] else "") if x) or None,
      "Akun tanpa password bisa dimasuki siapa saja; UID 0 ganda berarti ada akun dengan hak penuh yang tidak terlihat.",
      "Kunci atau hapus akun tersebut.", 0.5, "Tidak ada akun tanpa password atau UID 0 ganda."),
    R("SEC-07", "Tidak ada proteksi brute force", "Sedang", "Keamanan",
      lambda f: "fail2ban tidak aktif" if not f["network"]["fail2ban"] else None,
      "Percobaan login berulang tidak diblokir otomatis.",
      "Pasang fail2ban (atau CrowdSec) untuk SSH dan halaman login aplikasi.", 1,
      "Fail2ban aktif.", lambda f: bool(public_ports(f))),
    R("SEC-08", "TLS versi usang masih diaktifkan", "Sedang", "Keamanan",
      lambda f: "handshake berhasil dengan: " + ", ".join(p.upper().replace("_", ".") for p in f["web"]["legacy_tls"]) if f["web"]["legacy_tls"] else None,
      "TLS 1.0/1.1 punya kelemahan yang diketahui dan ditolak oleh standar kepatuhan seperti PCI-DSS.",
      "Batasi ke TLS 1.2 dan 1.3. Cek dulu bahwa tidak ada klien lama yang bergantung padanya.", 0.5,
      "TLS 1.0/1.1 ditolak (diuji dengan handshake sungguhan).", lambda f: f["web"]["nginx"] and 443 in public_ports(f)),
    R("SEC-09", "Versi web server terlihat di header", "Rendah", "Keamanan",
      lambda f: "header Server menampilkan nomor versi" if f["web"]["server_version_exposed"] else None,
      "Penyerang tahu versi persis dan bisa langsung mencari celah yang cocok.",
      "Set `server_tokens off;`.", 0.25, "Versi web server disembunyikan dari header.", lambda f: f["web"]["nginx"]),
    R("SEC-10", "Security header HTTP belum lengkap", "Sedang", "Keamanan",
      lambda f: f"{len(f['web']['security_headers'])} dari 5 header yang ada (ada: {', '.join(f['web']['security_headers']) or '-'})" if len(f["web"]["security_headers"]) < 4 else None,
      "Tanpa header ini browser tidak punya perlindungan tambahan terhadap clickjacking, sniffing, dan downgrade ke HTTP.",
      "Tambahkan HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, dan CSP yang sesuai aplikasi.", 1,
      "Security header lengkap.", lambda f: f["web"]["nginx"]),
    R("SEC-11", "Aplikasi web publik tanpa WAF", "Sedang", "Keamanan",
      lambda f: "tidak ada ModSecurity/WAF di konfigurasi Nginx" if not f["web"]["waf"] else None,
      "Serangan umum (SQL injection, XSS) langsung sampai ke aplikasi.",
      "Pasang ModSecurity + OWASP CRS, atau gunakan WAF dari CDN. Pantau false positive selama beberapa hari.", 3,
      "WAF aktif.", lambda f: f["web"]["nginx"] and bool({80, 443} & set(public_ports(f)))),
    R("SEC-12", "Directory listing aktif", "Sedang", "Keamanan",
      lambda f: "autoindex on" if f["web"]["autoindex_on"] else None,
      "Isi folder (termasuk file yang tidak sengaja ada di sana) bisa dibaca siapa saja.",
      "Set `autoindex off;`.", 0.25, "Directory listing mati.", lambda f: f["web"]["nginx"]),
    R("SEC-13", "Sertifikat TLS bermasalah", "Sedang", "Keamanan", _cert,
      "Pengunjung melihat peringatan keamanan, dan sertifikat kedaluwarsa membuat situs tidak bisa dibuka.",
      "Pakai sertifikat dari CA tepercaya (mis. Let's Encrypt) dengan pembaruan otomatis.", 1,
      "Sertifikat TLS valid.", lambda f: bool(f["web"]["certs"])),
    R("SEC-14", "HTTP tidak dialihkan ke HTTPS", "Rendah", "Keamanan",
      lambda f: "port 80 tidak membalas dengan redirect 301/302 ke https" if not f["web"]["http_redirect"] else None,
      "Pengunjung yang membuka alamat http:// mengirim data tanpa enkripsi.",
      "Tambahkan redirect 301 dari port 80 ke HTTPS.", 0.25, "HTTP dialihkan ke HTTPS.",
      lambda f: f["web"]["nginx"] and bool(f["web"]["certs"]) and 80 in public_ports(f)),
    R("OPS-01", "Ada pembaruan keamanan yang belum dipasang", "Tinggi", "Pemeliharaan",
      lambda f: f"{f['updates']['security_pending']} pembaruan keamanan dan {f['updates']['pending']} pembaruan total tertunda" if f["updates"]["security_pending"] > 0 else None,
      "Celah yang sudah diketahui publik tetap terbuka di server ini.",
      "Pasang pembaruan di jam sepi, lalu restart layanan yang terdampak.", 1,
      "Tidak ada pembaruan keamanan tertunda."),
    R("OPS-02", "Pembaruan keamanan otomatis tidak aktif", "Sedang", "Pemeliharaan",
      lambda f: "unattended-upgrades tidak aktif" if not f["updates"]["auto_updates"] else None,
      "Server akan kembali tertinggal setelah dibersihkan, kecuali ada yang rutin memperbaruinya.",
      "Aktifkan pembaruan keamanan otomatis dan jadwalkan reboot terkontrol.", 0.5,
      "Pembaruan keamanan otomatis aktif."),
    R("OPS-03", "Server butuh reboot", "Rendah", "Pemeliharaan",
      lambda f: "file /var/run/reboot-required ada" if f["updates"]["reboot_required"] else None,
      "Pembaruan kernel/library belum berlaku sampai server di-reboot.",
      "Jadwalkan reboot di jam sepi.", 0.25, "Tidak butuh reboot."),
    R("OPS-04", "Sistem operasi mendekati atau melewati akhir dukungan", "Tinggi", "Pemeliharaan", _eol,
      "Setelah dukungan habis, celah baru tidak lagi diperbaiki.",
      "Rencanakan upgrade OS atau migrasi ke server baru sebelum tanggalnya.", 8, "Versi OS masih didukung vendor."),
    R("OPS-05", "Ada layanan systemd yang gagal", "Sedang", "Pemeliharaan",
      lambda f: ", ".join(f["services"]["failed"]) or None,
      "Fungsi yang diharapkan berjalan sebenarnya mati tanpa ada yang menyadari.",
      "Periksa log tiap layanan dan perbaiki atau nonaktifkan yang tidak dipakai.", 1, "Tidak ada layanan yang gagal."),
    R("OPS-06", "Jam server tidak tersinkron", "Rendah", "Pemeliharaan",
      lambda f: "NTP tidak tersinkron" if not f["system"]["time_synced"] else None,
      "Log tidak bisa dikorelasikan dan sertifikat/token bisa ditolak karena waktu meleset.",
      "Aktifkan systemd-timesyncd atau chrony.", 0.25, "Waktu server tersinkron."),
    R("OPS-07", "Disk hampir penuh", "Tinggi", "Pemeliharaan", _disk,
      "Disk penuh membuat database dan aplikasi berhenti dan bisa merusak data.",
      "Bersihkan log/backup lama, atau tambah kapasitas, dan pasang alert di 80%.", 1, "Penggunaan disk aman (di bawah 85%)."),
    R("REL-01", "Tidak ada backup terjadwal", "Tinggi", "Keandalan", _backup,
      "Satu kesalahan (hapus data, ransomware, disk rusak) berarti data hilang permanen.",
      "Pasang backup otomatis harian, simpan salinan di luar server, dan uji restore berkala.", 4,
      "Ada backup terjadwal."),
    R("REL-02", "Backup terjadwal tapi tidak segar", "Tinggi", "Keandalan", _backup_stale,
      "Jadwal ada, tapi backup tidak benar-benar jalan atau hasilnya tidak tersimpan.",
      "Periksa log job backup dan pasang alert bila backup gagal.", 2, "Berkas backup terbaru masih segar."),
    R("REL-03", "Tidak ada monitoring dan alert", "Sedang", "Keandalan",
      lambda f: "tidak ada agen monitoring terdeteksi" if not f["monitoring"]["agents"] else None,
      "Gangguan baru diketahui dari keluhan pelanggan, bukan dari sistem.",
      "Pasang monitoring (uptime, CPU/RAM/disk, sertifikat) dengan notifikasi ke WhatsApp/Telegram/email.", 4,
      "Ada agen monitoring."),
    R("REL-04", "Log sistem tidak persisten", "Rendah", "Keandalan",
      lambda f: "/var/log/journal tidak ada: log hilang saat reboot" if not f["monitoring"]["journal_persistent"] else None,
      "Setelah insiden dan reboot, jejak penyebabnya hilang.",
      "Aktifkan journald persisten dan kirim log penting ke tempat terpisah.", 0.5, "Log sistem persisten."),
    R("REL-05", "Semua komponen bertumpu pada satu server", "Sedang", "Arsitektur", _spof,
      "Server mati, disk rusak, atau diserang berarti seluruh layanan mati sekaligus.",
      "Minimal: pisahkan database ke server/managed DB sendiri dan siapkan prosedur pemulihan terdokumentasi. Ideal: dua node di belakang load balancer.", 16,
      "Komponen tidak bertumpu pada satu server."),
    R("REL-06", "Container berjalan privileged", "Tinggi", "Keamanan",
      lambda f: f"{f['containers']['privileged']} container privileged" if f["containers"].get("privileged") else None,
      "Container privileged bisa mengambil alih host jika aplikasinya dibobol.",
      "Hilangkan flag privileged dan beri hanya capability yang dibutuhkan.", 2, "Tidak ada container privileged.",
      lambda f: f["containers"].get("docker", False)),
]


def evaluate(facts: dict) -> tuple[list[dict], list[str]]:
    """Kembalikan (daftar temuan, daftar hal yang sudah baik)."""
    findings, good = [], []
    for r in RULES:
        if not r.applies(facts):
            continue
        evidence = r.check(facts)
        if evidence:
            findings.append({"id": r.id, "title": r.title, "severity": r.severity, "category": r.category,
                             "evidence": evidence, "impact": r.impact, "fix": r.fix, "hours": r.hours})
        else:
            good.append(r.good)
    findings.sort(key=lambda x: (SEVERITIES.index(x["severity"]), x["id"]))
    return findings, good
