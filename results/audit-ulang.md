# Laporan Audit Arsitektur IT: Toko Demo (server lab, fiktif)

- Server: `web-lab-01` (Ubuntu 24.04.5 LTS)
- Data dikumpulkan: 2026-10-29T08:07:42+00:00 (hanya baca, tidak ada perubahan ke server)

## 1. Ringkasan eksekutif

**Temuan: 6** (Tinggi 2, Sedang 3, Rendah 1). Indeks kesehatan **67/100**. Estimasi pengerjaan seluruh temuan: **±26.5 jam kerja**.

**Dibanding audit sebelumnya:** indeks 26 → 67, temuan 14 → 6; 9 selesai, 5 masih ada, 1 baru.

> Indeks = 100 dikurangi bobot temuan (Tinggi 10, Sedang 4, Rendah 1). Ini indikator kasar untuk membandingkan dari waktu ke waktu, bukan standar baku.

## 2. Gambaran arsitektur saat ini

```
Internet
   │  port TCP terbuka ke publik: 22, 80, 443
   ▼  firewall: aktif
[Nginx] ──► [PHP-FPM] ──► [MariaDB/MySQL]
   server tunggal: Ubuntu 24.04.5 LTS, 2 vCPU, 1967 MB RAM
```

## 3. Temuan

### Prioritas Tinggi (2)

**OPS-01 · Ada pembaruan keamanan yang belum dipasang** (Pemeliharaan, ±1 jam)

- Bukti: 10 pembaruan keamanan dan 18 pembaruan total tertunda
- Dampak: Celah yang sudah diketahui publik tetap terbuka di server ini.
- Rekomendasi: Pasang pembaruan di jam sepi, lalu restart layanan yang terdampak.

**REL-01 · Tidak ada backup terjadwal** (Keandalan, ±4 jam)

- Bukti: tidak ditemukan cron/timer backup (kata kunci: backup, dump, restic, borg, rclone, dll)
- Dampak: Satu kesalahan (hapus data, ransomware, disk rusak) berarti data hilang permanen.
- Rekomendasi: Pasang backup otomatis harian, simpan salinan di luar server, dan uji restore berkala.

### Prioritas Sedang (3)

**REL-03 · Tidak ada monitoring dan alert** (Keandalan, ±4 jam)

- Bukti: tidak ada agen monitoring terdeteksi
- Dampak: Gangguan baru diketahui dari keluhan pelanggan, bukan dari sistem.
- Rekomendasi: Pasang monitoring (uptime, CPU/RAM/disk, sertifikat) dengan notifikasi ke WhatsApp/Telegram/email.

**REL-05 · Semua komponen bertumpu pada satu server** (Arsitektur, ±16 jam)

- Bukti: web server dan database berjalan di server yang sama: satu server mati berarti semuanya mati
- Dampak: Server mati, disk rusak, atau diserang berarti seluruh layanan mati sekaligus.
- Rekomendasi: Minimal: pisahkan database ke server/managed DB sendiri dan siapkan prosedur pemulihan terdokumentasi. Ideal: dua node di belakang load balancer.

**SEC-13 · Sertifikat TLS bermasalah** (Keamanan, ±1 jam)

- Bukti: /etc/ssl/lab/web.crt self-signed (browser pengunjung akan menampilkan peringatan)
- Dampak: Pengunjung melihat peringatan keamanan, dan sertifikat kedaluwarsa membuat situs tidak bisa dibuka.
- Rekomendasi: Pakai sertifikat dari CA tepercaya (mis. Let's Encrypt) dengan pembaruan otomatis.

### Prioritas Rendah (1)

**SEC-15 · File sensitif masih tersimpan di webroot** (Keamanan, ±0.5 jam)

- Bukti: tersimpan tapi diblokir web server: /var/www/html/.git, /var/www/html/backup.sql, /var/www/html/.env
- Dampak: Sekarang diblokir, tapi satu kesalahan konfigurasi atau pembaruan web server bisa membukanya lagi.
- Rekomendasi: Pindahkan file ke luar webroot. Blokir di web server hanya sebagai lapisan kedua.

## 4. Rencana perbaikan

**Minggu ini (0-7 hari)**: ±5 jam

- OPS-01 Ada pembaruan keamanan yang belum dipasang
- REL-01 Tidak ada backup terjadwal

**Bulan ini (≤ 30 hari)**: ±21 jam

- REL-03 Tidak ada monitoring dan alert
- REL-05 Semua komponen bertumpu pada satu server
- SEC-13 Sertifikat TLS bermasalah

**Kuartal ini (≤ 90 hari)**: ±0.5 jam

- SEC-15 File sensitif masih tersimpan di webroot

## 5. Perubahan sejak audit sebelumnya

**Sudah selesai (9)**

- SEC-03 Tidak ada firewall aktif (Tinggi)
- SEC-05 File sensitif bisa diunduh lewat web server (Tinggi)
- SEC-07 Tidak ada proteksi brute force (Sedang)
- SEC-08 TLS versi usang masih diaktifkan (Sedang)
- SEC-10 Security header HTTP belum lengkap (Sedang)
- SEC-11 Aplikasi web publik tanpa WAF (Sedang)
- SEC-12 Directory listing aktif (Sedang)
- SEC-09 Versi web server terlihat di header (Rendah)
- SEC-14 HTTP tidak dialihkan ke HTTPS (Rendah)

**Masih ada (5)**

- OPS-01 Ada pembaruan keamanan yang belum dipasang (Tinggi)
- REL-01 Tidak ada backup terjadwal (Tinggi)
- REL-03 Tidak ada monitoring dan alert (Sedang)
- REL-05 Semua komponen bertumpu pada satu server (Sedang)
- SEC-13 Sertifikat TLS bermasalah (Sedang)

**Temuan baru (1)**

- SEC-15 File sensitif masih tersimpan di webroot (Rendah)

## 6. Yang sudah baik

- Login SSH root ditolak.
- Login SSH hanya dengan key.
- Firewall aktif.
- Tidak ada database/layanan internal yang terbuka ke publik.
- Tidak ada file sensitif yang bisa diunduh lewat web server.
- Tidak ada akun tanpa password atau UID 0 ganda.
- Fail2ban aktif.
- TLS 1.0/1.1 ditolak (diuji dengan handshake sungguhan).
- Versi web server disembunyikan dari header.
- Security header lengkap.
- WAF aktif.
- Directory listing mati.
- HTTP dialihkan ke HTTPS.
- Pembaruan keamanan otomatis aktif.
- Tidak butuh reboot.
- Versi OS masih didukung vendor.
- Tidak ada layanan yang gagal.
- Waktu server tersinkron.
- Penggunaan disk aman (di bawah 85%).
- Berkas backup terbaru masih segar.
- Log sistem persisten.

## Batasan audit

- Audit ini memeriksa kondisi teknis server pada saat pengumpulan data. Tidak mencakup kode aplikasi, proses bisnis, kepatuhan hukum, atau infrastruktur di luar server ini.
- Temuan berbasis aturan baku. Prioritas akhir tetap perlu disesuaikan dengan konteks bisnis (mis. data apa yang disimpan, berapa biaya jika layanan mati sehari).
- Estimasi jam adalah perkiraan kerja satu engineer, belum termasuk koordinasi, pengujian di lingkungan klien, dan jendela perawatan.
