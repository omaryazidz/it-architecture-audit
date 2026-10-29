"""Uji mesin aturan audit dan pembuat laporan dengan fakta sintetis. Jalankan: python run_tests.py"""
import copy
import datetime as dt
import unittest

import collect
from audit import report, rules

HEALTHY = {
    "collected_at": "2026-10-29T00:00:00+00:00",
    "system": {"hostname": "srv-sehat", "os": "Ubuntu 24.04.5 LTS", "os_id": "ubuntu", "os_version": "24.04", "kernel": "6.8",
               "uptime_days": 10, "cpus": 2, "memory_mb": 4096, "virtualization": "kvm",
               "disks": [{"mount": "/", "used_pct": 40, "size_gb": 50}], "swap_mb": 2048, "time_synced": True, "timezone": "UTC"},
    "updates": {"pending": 0, "security_pending": 0, "reboot_required": False, "auto_updates": True},
    "network": {"listening": [{"proto": "tcp", "address": "0.0.0.0", "port": 22, "public": True, "process": "sshd"},
                              {"proto": "tcp", "address": "0.0.0.0", "port": 443, "public": True, "process": "nginx"},
                              {"proto": "tcp", "address": "0.0.0.0", "port": 80, "public": True, "process": "nginx"}],
                "firewall": {"ufw_active": True, "firewalld_active": False, "nft_rules": 0}, "fail2ban": True},
    "ssh": {"present": True, "port": "22", "permitrootlogin": "no", "passwordauthentication": "no", "maxauthtries": "3", "x11forwarding": "no"},
    "accounts": {"login_users": ["admin"], "sudo_users": ["admin"], "extra_uid0": [], "empty_password": [], "keys": {"admin": True}},
    "services": {"running": ["nginx", "ssh"], "failed": []},
    "web": {"nginx": True, "apache": False, "server_version_exposed": False, "ssl_protocols": ["TLSv1.2", "TLSv1.3"], "legacy_tls": [], "autoindex_on": False,
            "waf": True, "security_headers": ["Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
                                              "X-Content-Type-Options", "X-Frame-Options"],
            "roots": ["/var/www/html"], "sensitive_files": [], "sensitive_downloadable": [], "certs": [{"path": "/etc/ssl/a.crt", "days_left": 200, "self_signed": False}],
            "http_redirect": True},
    "database": {"postgresql": False, "mysql": False},
    "backup": {"scheduled_jobs": ["pg-backup.timer"], "newest_backup_age_days": 0.5},
    "containers": {"docker": False},
    "monitoring": {"agents": ["node_exporter"], "journal_persistent": True, "logrotate": True},
}


def facts(mutate=None):
    f = copy.deepcopy(HEALTHY)
    if mutate:
        mutate(f)
    return f


def ids(f, **kw):
    return {x["id"]: x for x in rules.evaluate(f)[0]}


# aturan -> (cara merusak fakta sehat, tingkat keparahan yang diharapkan)
BREAKERS = {
    "SEC-01": (lambda f: f["ssh"].update(permitrootlogin="yes"), "Tinggi"),
    "SEC-02": (lambda f: f["ssh"].update(passwordauthentication="yes"), "Tinggi"),
    "SEC-03": (lambda f: f["network"]["firewall"].update(ufw_active=False), "Tinggi"),
    "SEC-04": (lambda f: f["network"]["listening"].append({"proto": "tcp", "address": "0.0.0.0", "port": 3306, "public": True, "process": "mysqld"}), "Tinggi"),
    "SEC-05": (lambda f: f["web"].update(sensitive_files=["/var/www/html/.env"], sensitive_downloadable=["/var/www/html/.env"]), "Tinggi"),
    "SEC-15": (lambda f: f["web"].update(sensitive_files=["/var/www/html/.env"]), "Rendah"),
    "SEC-06": (lambda f: f["accounts"].update(empty_password=["tamu"]), "Tinggi"),
    "SEC-07": (lambda f: f["network"].update(fail2ban=False), "Sedang"),
    "SEC-08": (lambda f: f["web"].update(legacy_tls=["tls1"]), "Sedang"),
    "SEC-09": (lambda f: f["web"].update(server_version_exposed=True), "Rendah"),
    "SEC-10": (lambda f: f["web"].update(security_headers=["X-Frame-Options"]), "Sedang"),
    "SEC-11": (lambda f: f["web"].update(waf=False), "Sedang"),
    "SEC-12": (lambda f: f["web"].update(autoindex_on=True), "Sedang"),
    "SEC-13": (lambda f: f["web"]["certs"][0].update(self_signed=True), "Sedang"),
    "SEC-14": (lambda f: f["web"].update(http_redirect=False), "Rendah"),
    "OPS-01": (lambda f: f["updates"].update(pending=12, security_pending=5), "Tinggi"),
    "OPS-02": (lambda f: f["updates"].update(auto_updates=False), "Sedang"),
    "OPS-03": (lambda f: f["updates"].update(reboot_required=True), "Rendah"),
    "OPS-04": (lambda f: f["system"].update(os="Ubuntu 20.04 LTS", os_version="20.04"), "Tinggi"),
    "OPS-05": (lambda f: f["services"].update(failed=["cron.service"]), "Sedang"),
    "OPS-06": (lambda f: f["system"].update(time_synced=False), "Rendah"),
    "OPS-07": (lambda f: f["system"]["disks"][0].update(used_pct=92), "Tinggi"),
    "REL-01": (lambda f: f["backup"].update(scheduled_jobs=[]), "Tinggi"),
    "REL-02": (lambda f: f["backup"].update(newest_backup_age_days=9), "Tinggi"),
    "REL-03": (lambda f: f["monitoring"].update(agents=[]), "Sedang"),
    "REL-04": (lambda f: f["monitoring"].update(journal_persistent=False), "Rendah"),
    "REL-05": (lambda f: f["database"].update(mysql=True), "Sedang"),
    "REL-06": (lambda f: f.update(containers={"docker": True, "running": 2, "privileged": 1}), "Tinggi"),
}


class AuditTest(unittest.TestCase):
    def test_01_server_sehat_tidak_menghasilkan_temuan(self):
        """Server yang sehat -> 0 temuan, indeks 100, dan daftar 'yang sudah baik' terisi"""
        findings, good = rules.evaluate(facts())
        self.assertEqual(findings, [])
        self.assertGreater(len(good), 15)
        self.assertEqual(report.risk_index(findings), 100)

    def test_02_setiap_aturan_terpicu_dengan_tingkat_yang_benar(self):
        """Setiap dari 28 aturan terpicu tepat oleh satu kerusakan dan memakai tingkat keparahan yang benar"""
        self.assertEqual(set(BREAKERS), {r.id for r in rules.RULES}, "ada aturan yang belum diuji")
        for rid, (mutate, sev) in BREAKERS.items():
            with self.subTest(rule=rid):
                found = ids(facts(mutate))
                self.assertIn(rid, found)
                self.assertEqual(found[rid]["severity"], sev)
                self.assertTrue(found[rid]["evidence"])

    def test_03_satu_kerusakan_tidak_memicu_aturan_lain(self):
        """Merusak satu hal tidak menimbulkan temuan lain yang tidak terkait (tidak ada false positive silang)"""
        for rid, (mutate, _) in BREAKERS.items():
            with self.subTest(rule=rid):
                self.assertEqual(set(ids(facts(mutate))) - {rid}, set(), rid)

    def test_04_aturan_web_dilewati_bila_tidak_ada_web_server(self):
        """Tanpa Nginx -> aturan khusus web tidak berlaku (tidak jadi temuan dan tidak dipuji)"""
        f = facts(lambda f: (f["web"].update(nginx=False, ssl_protocols=[], certs=[], waf=False, server_version_exposed=True,
                                             security_headers=[], http_redirect=False, legacy_tls=["tls1"]),
                             f["network"]["listening"].pop()))
        found = ids(f)
        self.assertFalse([i for i in found if i in ("SEC-08", "SEC-09", "SEC-10", "SEC-11", "SEC-12", "SEC-13", "SEC-14", "SEC-15")])
        self.assertNotIn(next(r for r in rules.RULES if r.id == "SEC-09").good, rules.evaluate(f)[1])

    def test_05_firewall_tidak_dinilai_bila_tidak_ada_port_publik(self):
        """Server tanpa port publik tidak dituduh 'tanpa firewall'"""
        f = facts(lambda f: (f["network"]["firewall"].update(ufw_active=False), f["network"].update(listening=[])))
        self.assertNotIn("SEC-03", ids(f))

    def test_06_eol_os_dihitung_dari_tanggal(self):
        """OS lewat EOL, mendekati EOL (<12 bulan), dan masih aman dibedakan dengan benar"""
        f = facts(lambda f: f["system"].update(os="Ubuntu 22.04", os_version="22.04"))
        self.assertIsNone(rules._eol(f, today=dt.date(2025, 1, 1)))
        self.assertIn("kurang dari 12 bulan", rules._eol(f, today=dt.date(2026, 10, 1)))
        self.assertIn("sudah melewati", rules._eol(f, today=dt.date(2027, 7, 1)))

    def test_07_ssh_prohibit_password_bukan_temuan_root(self):
        """PermitRootLogin 'prohibit-password' (hanya key) dianggap aman"""
        self.assertNotIn("SEC-01", ids(facts(lambda f: f["ssh"].update(permitrootlogin="prohibit-password"))))

    def test_08_indeks_kesehatan_memakai_bobot_yang_dijelaskan(self):
        """1 Tinggi + 1 Sedang + 1 Rendah -> indeks 100-10-4-1 = 85; tidak pernah di bawah 0"""
        mix = [{"severity": "Tinggi"}, {"severity": "Sedang"}, {"severity": "Rendah"}]
        self.assertEqual(report.risk_index(mix), 85)
        self.assertEqual(report.risk_index([{"severity": "Tinggi"}] * 20), 0)

    def test_09_laporan_pembanding_memisahkan_selesai_tersisa_dan_baru(self):
        """Audit ulang: temuan yang beres, yang masih ada, dan yang baru muncul dipisah dengan benar"""
        before = facts(lambda f: (BREAKERS["SEC-01"][0](f), BREAKERS["SEC-09"][0](f), BREAKERS["REL-01"][0](f)))
        after = facts(lambda f: (BREAKERS["REL-01"][0](f), BREAKERS["OPS-03"][0](f)))
        c = report.build(after, "X", before)["compare"]
        self.assertEqual([f["id"] for f in c["resolved"]], ["SEC-01", "SEC-09"])
        self.assertEqual([f["id"] for f in c["remaining"]], ["REL-01"])
        self.assertEqual([f["id"] for f in c["new"]], ["OPS-03"])

    def test_10_laporan_html_dan_markdown_lengkap_dan_aman_dari_injeksi(self):
        """Nama host berisi tag <script> -> di-escape di HTML; semua bagian laporan ada"""
        f = facts(lambda f: (f["system"].update(hostname="<script>alert(1)</script>"), BREAKERS["SEC-05"][0](f)))
        r = report.build(f, "Toko <b>Demo</b>")
        h, m = report.to_html(r), report.to_markdown(r)
        self.assertNotIn("<script>alert(1)", h)
        self.assertIn("&lt;script&gt;", h)
        for part in ("Ringkasan eksekutif", "Gambaran arsitektur", "Temuan", "Rencana perbaikan", "Yang sudah baik", "Batasan audit"):
            self.assertIn(part, m)
            self.assertIn(part, h)

    def test_11_diagram_arsitektur_mencerminkan_fakta(self):
        """Diagram menampilkan port publik, status firewall, dan komponen yang terdeteksi"""
        f = facts(lambda f: (f["network"]["firewall"].update(ufw_active=False), f["services"].update(running=["nginx", "php8.3-fpm", "mariadb"]),
                             f["database"].update(mysql=True)))
        d = report.architecture(f)
        self.assertIn("22, 80, 443", d)
        self.assertIn("TIDAK ADA", d)
        self.assertIn("[Nginx] ──► [PHP-FPM] ──► [MariaDB/MySQL]", d)

    def test_12_definisi_aturan_konsisten(self):
        """Semua aturan punya id unik, tingkat valid, dan isi dampak/rekomendasi/jam yang terisi"""
        self.assertEqual(len({r.id for r in rules.RULES}), len(rules.RULES))
        for r in rules.RULES:
            self.assertIn(r.severity, rules.SEVERITIES)
            self.assertTrue(r.impact and r.fix and r.good and r.hours > 0, r.id)

    # ---------- kolektor ----------
    def test_13_parse_ss_membedakan_port_publik_dan_lokal(self):
        """Keluaran `ss`: 0.0.0.0 dan [::] publik, 127.0.0.1 lokal; nama proses terbaca"""
        out = ('tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=5))\n'
               'tcp LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=2,fd=21))\n'
               'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=3,fd=4))\n'
               'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n')
        p = {x["port"]: x for x in collect.parse_ss(out)}
        self.assertTrue(p[80]["public"] and p[22]["public"])
        self.assertFalse(p[3306]["public"])
        self.assertEqual((p[80]["process"], p[3306]["process"], p[22]["address"]), ("nginx", "mariadbd", "::"))

    def test_13b_resolver_lokal_dengan_akhiran_interface_bukan_port_publik(self):
        """'127.0.0.53%lo:53' (systemd-resolved) adalah loopback -> tidak boleh dilaporkan sebagai port publik"""
        out = "\n".join([
            'tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=9,fd=15))',
            "tcp LISTEN 0 4096 127.0.0.54:53 0.0.0.0:*",
            "tcp LISTEN 0 128 *:8080 *:*",
        ])
        parsed = collect.parse_ss(out)
        dns = [x for x in parsed if x["port"] == 53]
        self.assertEqual(len(dns), 2)  # kedua baris port 53 diperiksa, tidak saling menimpa
        self.assertTrue(all(not x["public"] for x in dns))
        self.assertTrue(next(x for x in parsed if x["port"] == 8080)["public"])  # wildcard = semua interface

    def test_13c_job_bawaan_sistem_bukan_backup_data(self):
        """dpkg-db-backup dan cron bawaan paket tidak dihitung sebagai backup; restic/pg_dump/rclone dihitung"""
        for name in ("dpkg-db-backup.timer", "/etc/cron.daily/dpkg", "/etc/cron.daily/passwd", "/etc/cron.daily/logrotate"):
            self.assertFalse(collect.is_backup_job(name, "backup status file"), name)
        self.assertTrue(collect.is_backup_job("/etc/cron.d/db", "0 2 * * * root pg_dump -Fc app > /srv/x"))
        self.assertTrue(collect.is_backup_job("pg-backup.timer"))
        self.assertTrue(collect.is_backup_job("/etc/cron.daily/restic-offsite", "restic backup /srv"))

    def test_14_parse_df_hanya_disk_nyata(self):
        """Keluaran `df`: filesystem virtual (tmpfs) diabaikan, persen dan ukuran terbaca"""
        out = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
               "/dev/vda1 51474044 20589618 30867426 41% /\n"
               "tmpfs 2023376 0 2023376 0% /dev/shm\n")
        self.assertEqual(collect.parse_df(out), [{"mount": "/", "used_pct": 41, "size_gb": 49.1}])


if __name__ == "__main__":
    unittest.main()
