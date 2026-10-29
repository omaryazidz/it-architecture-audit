# Laporan Audit Arsitektur IT: Toko Demo (server lab, fiktif)

- Server: `web-lab-01` (Ubuntu 24.04.5 LTS)
- Data dikumpulkan: 2026-10-29T08:07:02+00:00 (hanya baca, tidak ada perubahan ke server)

## 1. Ringkasan eksekutif

**Temuan: 14** (Tinggi 4, Sedang 8, Rendah 2). Indeks kesehatan **26/100**. Estimasi pengerjaan seluruh temuan: **±33.75 jam kerja**.

> Indeks = 100 dikurangi bobot temuan (Tinggi 10, Sedang 4, Rendah 1). Ini indikator kasar untuk membandingkan dari waktu ke waktu, bukan standar baku.

## 2. Gambaran arsitektur saat ini

```
Internet
   │  port TCP terbuka ke publik: 22, 80, 443
   ▼  firewall: TIDAK ADA
[Nginx] ──► [PHP-FPM] ──► [MariaDB/MySQL]
   server tunggal: Ubuntu 24.04.5 LTS, 2 vCPU, 1967 MB RAM
```

## 3. Temuan

### Prioritas Tinggi (4)

**OPS-01 · Ada pembaruan keamanan yang belum dipasang** (Pemeliharaan, ±1 jam)

- Bukti: 10 pembaruan keamanan dan 18 pembaruan total tertunda
- Dampak: Celah yang sudah diketahui publik tetap terbuka di server ini.
- Rekomendasi: Pasang pembaruan di jam sepi, lalu restart layanan yang terdampak.

**REL-01 · Tidak ada backup terjadwal** (Keandalan, ±4 jam)

- Bukti: tidak ditemukan cron/timer backup (kata kunci: backup, dump, restic, borg, rclone, dll)
- Dampak: Satu kesalahan (hapus data, ransomware, disk rusak) berarti data hilang permanen.
- Rekomendasi: Pasang backup otomatis harian, simpan salinan di luar server, dan uji restore berkala.

**SEC-03 · Tidak ada firewall aktif** (Keamanan, ±1 jam)

- Bukti: firewall tidak aktif; port TCP terbuka ke publik: 22, 80, 443
- Dampak: Setiap layanan yang kebetulan berjalan langsung terpapar ke internet.
- Rekomendasi: Aktifkan firewall dengan kebijakan default tolak, buka hanya port yang dibutuhkan.

**SEC-05 · File sensitif bisa diunduh lewat web server** (Keamanan, ±0.5 jam)

- Bukti: terunduh (HTTP 200): /var/www/html/.git, /var/www/html/backup.sql, /var/www/html/.env
- Dampak: File seperti .env, .git, atau dump database membuka password dan seluruh kode sumber kepada siapa saja.
- Rekomendasi: Pindahkan file ke luar webroot dan blokir dotfile serta ekstensi sensitif di web server.

### Prioritas Sedang (8)

**REL-03 · Tidak ada monitoring dan alert** (Keandalan, ±4 jam)

- Bukti: tidak ada agen monitoring terdeteksi
- Dampak: Gangguan baru diketahui dari keluhan pelanggan, bukan dari sistem.
- Rekomendasi: Pasang monitoring (uptime, CPU/RAM/disk, sertifikat) dengan notifikasi ke WhatsApp/Telegram/email.

**REL-05 · Semua komponen bertumpu pada satu server** (Arsitektur, ±16 jam)

- Bukti: web server dan database berjalan di server yang sama: satu server mati berarti semuanya mati
- Dampak: Server mati, disk rusak, atau diserang berarti seluruh layanan mati sekaligus.
- Rekomendasi: Minimal: pisahkan database ke server/managed DB sendiri dan siapkan prosedur pemulihan terdokumentasi. Ideal: dua node di belakang load balancer.

**SEC-07 · Tidak ada proteksi brute force** (Keamanan, ±1 jam)

- Bukti: fail2ban tidak aktif
- Dampak: Percobaan login berulang tidak diblokir otomatis.
- Rekomendasi: Pasang fail2ban (atau CrowdSec) untuk SSH dan halaman login aplikasi.

**SEC-08 · TLS versi usang masih diaktifkan** (Keamanan, ±0.5 jam)

- Bukti: handshake berhasil dengan: TLS1, TLS1.1
- Dampak: TLS 1.0/1.1 punya kelemahan yang diketahui dan ditolak oleh standar kepatuhan seperti PCI-DSS.
- Rekomendasi: Batasi ke TLS 1.2 dan 1.3. Cek dulu bahwa tidak ada klien lama yang bergantung padanya.

**SEC-10 · Security header HTTP belum lengkap** (Keamanan, ±1 jam)

- Bukti: 0 dari 5 header yang ada (ada: -)
- Dampak: Tanpa header ini browser tidak punya perlindungan tambahan terhadap clickjacking, sniffing, dan downgrade ke HTTP.
- Rekomendasi: Tambahkan HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, dan CSP yang sesuai aplikasi.

**SEC-11 · Aplikasi web publik tanpa WAF** (Keamanan, ±3 jam)

- Bukti: tidak ada ModSecurity/WAF di konfigurasi Nginx
- Dampak: Serangan umum (SQL injection, XSS) langsung sampai ke aplikasi.
- Rekomendasi: Pasang ModSecurity + OWASP CRS, atau gunakan WAF dari CDN. Pantau false positive selama beberapa hari.

**SEC-12 · Directory listing aktif** (Keamanan, ±0.25 jam)

- Bukti: autoindex on
- Dampak: Isi folder (termasuk file yang tidak sengaja ada di sana) bisa dibaca siapa saja.
- Rekomendasi: Set `autoindex off;`.

**SEC-13 · Sertifikat TLS bermasalah** (Keamanan, ±1 jam)

- Bukti: /etc/ssl/lab/web.crt self-signed (browser pengunjung akan menampilkan peringatan)
- Dampak: Pengunjung melihat peringatan keamanan, dan sertifikat kedaluwarsa membuat situs tidak bisa dibuka.
- Rekomendasi: Pakai sertifikat dari CA tepercaya (mis. Let's Encrypt) dengan pembaruan otomatis.

### Prioritas Rendah (2)

**SEC-09 · Versi web server terlihat di header** (Keamanan, ±0.25 jam)

- Bukti: header Server menampilkan nomor versi
- Dampak: Penyerang tahu versi persis dan bisa langsung mencari celah yang cocok.
- Rekomendasi: Set `server_tokens off;`.

**SEC-14 · HTTP tidak dialihkan ke HTTPS** (Keamanan, ±0.25 jam)

- Bukti: port 80 tidak membalas dengan redirect 301/302 ke https
- Dampak: Pengunjung yang membuka alamat http:// mengirim data tanpa enkripsi.
- Rekomendasi: Tambahkan redirect 301 dari port 80 ke HTTPS.

## 4. Rencana perbaikan

**Minggu ini (0-7 hari)**: ±6.5 jam

- OPS-01 Ada pembaruan keamanan yang belum dipasang
- REL-01 Tidak ada backup terjadwal
- SEC-03 Tidak ada firewall aktif
- SEC-05 File sensitif bisa diunduh lewat web server

**Bulan ini (≤ 30 hari)**: ±26.75 jam

- REL-03 Tidak ada monitoring dan alert
- REL-05 Semua komponen bertumpu pada satu server
- SEC-07 Tidak ada proteksi brute force
- SEC-08 TLS versi usang masih diaktifkan
- SEC-10 Security header HTTP belum lengkap
- SEC-11 Aplikasi web publik tanpa WAF
- SEC-12 Directory listing aktif
- SEC-13 Sertifikat TLS bermasalah

**Kuartal ini (≤ 90 hari)**: ±0.5 jam

- SEC-09 Versi web server terlihat di header
- SEC-14 HTTP tidak dialihkan ke HTTPS

## 5. Yang sudah baik

- Login SSH root ditolak.
- Login SSH hanya dengan key.
- Tidak ada database/layanan internal yang terbuka ke publik.
- Webroot bersih dari file sensitif.
- Tidak ada akun tanpa password atau UID 0 ganda.
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
