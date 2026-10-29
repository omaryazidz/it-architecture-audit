# Audit Arsitektur IT: Dari Data Server ke Laporan yang Bisa Ditindaklanjuti

Konsultasi dan audit arsitektur IT menghasilkan dokumen, jadi portofolionya adalah **contoh laporan nyata**, bukan teori. Project ini berisi dua alat dan satu laporan contoh:

1. **Kolektor** ([`collect.py`](collect.py)) mengumpulkan fakta dari server Linux. Sifatnya **hanya membaca**, tidak mengubah apa pun.
2. **Mesin audit** ([`audit/`](audit/)) mengubah fakta menjadi temuan berprioritas, diagram arsitektur, estimasi jam kerja, dan rencana perbaikan, dalam format Markdown dan HTML (siap dicetak jadi PDF).
3. **Laporan contoh** di [`results/`](results/): audit sebuah server toko online fiktif, perbaikannya, lalu **audit ulang** yang membandingkan kondisi sebelum dan sesudah.

## Laporan contoh

Server klien fiktif "Toko Demo": WordPress + Nginx + MariaDB di satu VM Ubuntu 24.04 dengan konfigurasi bawaan (server lab yang sama dengan project hardening web).

| | Audit awal | Audit ulang |
|---|---:|---:|
| Temuan | **14** (4 tinggi, 8 sedang, 2 rendah) | **6** (2 tinggi, 3 sedang, 1 rendah) |
| Indeks kesehatan | **26/100** | **67/100** |
| Estimasi pengerjaan sisa | ±33,75 jam | ±26,5 jam |

Laporan lengkap: [audit-awal.html](results/audit-awal.html) · [audit-awal.md](results/audit-awal.md) · [audit-ulang.html](results/audit-ulang.html) · [audit-ulang.md](results/audit-ulang.md). Fakta mentahnya ada di [facts-before.json](results/facts-before.json) dan [facts-after.json](results/facts-after.json).

Di antara dua audit, server diperbaiki dengan script dari project hardening OS dan hardening web. Hasil audit ulang: **9 temuan selesai, 5 masih ada, 1 baru**.

**Temuan yang selesai:** firewall, brute force, security header, WAF, directory listing, TLS lama, versi server terlihat, redirect HTTPS, dan file sensitif yang bisa diunduh.

**Temuan yang masih ada, dan itu disengaja.** Sisanya bukan hal yang bisa selesai dengan script. Semuanya butuh keputusan bisnis atau biaya:
- tidak ada backup dan tidak ada monitoring (butuh memilih tempat penyimpanan dan alat),
- web dan database bertumpu pada satu server (±16 jam, butuh anggaran server tambahan),
- sertifikat self-signed (butuh domain sungguhan),
- pembaruan keamanan tertunda (butuh jendela perawatan yang disepakati).

Temuan baru SEC-15 ("file sensitif masih tersimpan di webroot") muncul karena file `.env` dan `backup.sql` tidak lagi bisa diunduh (sudah diblokir), tapi masih ada di folder web dan sebaiknya dipindahkan.

Isi tiap laporan: ringkasan eksekutif, diagram arsitektur dari fakta, temuan (bukti, dampak, rekomendasi, estimasi jam), rencana perbaikan per prioritas, bagian "yang sudah baik", dan batasan audit.

## Yang diperiksa (28 aturan)

| Kategori | Contoh |
|---|---|
| Keamanan | login root dan password SSH, firewall, port database terbuka, file sensitif yang **benar-benar bisa diunduh**, TLS usang (diuji dengan handshake), security header, WAF, sertifikat, container privileged |
| Pemeliharaan | pembaruan keamanan tertunda, update otomatis, OS mendekati akhir dukungan, layanan gagal, disk hampir penuh, sinkronisasi waktu |
| Keandalan | backup (ada, segar), monitoring, log persisten |
| Arsitektur | semua komponen bertumpu pada satu server |

Kolektor tidak membaca isi file rahasia. Untuk `/etc/shadow` hanya dicek apakah kolom password kosong, dan untuk webroot hanya **nama** file sensitif yang dilaporkan.

## Kesalahan yang ditemukan lewat pengujian

Audit yang salah lebih berbahaya daripada tidak ada audit, jadi ini yang paling saya jaga. Menjalankan alat ini ke server lab sungguhan membongkar empat kesalahan di versi awal, semuanya sudah diperbaiki:

1. **Temuan backup yang salah.** Cron bawaan Ubuntu (`dpkg-db-backup`) kebetulan mengandung kata "backup" dan dianggap backup data. Sekarang job bawaan paket sistem diabaikan.
2. **Port 53 dianggap terbuka ke publik.** Itu `systemd-resolved` di `127.0.0.53%lo`. Akhiran `%lo` membuat deteksi loopback gagal.
3. **Membaca konfigurasi, bukan perilaku.** Daftar `TLSv1 TLSv1.1` dibaca dari `nginx.conf` bawaan, padahal server block sudah menimpanya, jadi TLS lama terus dilaporkan **setelah** diperbaiki. Baris yang di-comment (`# server_tokens off;`) juga ikut terhitung, sehingga masalah itu **terlewat** di audit pertama. Sekarang pemeriksaan web memakai uji langsung ke server: header HTTP asli, handshake TLS, dan kode respons tiap file sensitif.
4. **Tuduhan yang terlalu kasar.** Setelah file `.env` diblokir, laporan tetap berkata "bisa diunduh". Sekarang dibedakan: **bisa diunduh** (tinggi) dan **tersimpan tapi diblokir** (rendah).

## Hasil tes

```
python run_tests.py     ->  16/16 lulus
python tools/mutation_check.py     ->  12/12 kerusakan sengaja tertangkap
```

Tes memakai fakta sintetis: server sehat menghasilkan 0 temuan, dan setiap aturan terpicu tepat oleh satu kerusakan dengan tingkat keparahan yang benar tanpa memicu aturan lain. Uji mutasi merusak kode di 12 tempat. Waktu pertama dijalankan 4 kerusakan lolos, penyebabnya dua kelemahan pada tes saya sendiri (satu tes salah desain dan hasil `subTest` tidak ikut terhitung). Keduanya sudah diperbaiki ([results/mutation.txt](results/mutation.txt)).

## Pemakaian

Di server yang diaudit (Linux, butuh Python 3 dan root):

```bash
sudo python3 collect.py > facts.json
```

Di komputer mana pun (hanya Python, tanpa library tambahan):

```bash
python -m audit facts.json --client "Nama Klien" --out laporan
python -m audit facts-baru.json --before facts-lama.json --client "Nama Klien" --out laporan-ulang
```

Hasilnya `laporan.md` dan `laporan.html`. Buka HTML di browser lalu cetak ke PDF untuk dikirim ke klien.

## Batasan

- **Ini alat bantu, bukan pengganti konsultan.** Audit nyata juga mencakup wawancara dengan tim, pemetaan alur data dan proses bisnis, kebutuhan ketersediaan, dan anggaran. Itu tidak bisa dikumpulkan lewat script. Laporan dari alat ini menjadi bahan dasar, lalu prioritasnya disesuaikan dengan konteks bisnis.
- **Hanya satu server Linux per laporan**, dengan fokus web server Nginx. Apache, jaringan antar-server, cloud (IAM, security group), dan aplikasi yang berjalan di dalamnya belum diperiksa. Windows belum dicakup.
- **Berbasis aturan baku.** Tidak ada penilaian konteks, misalnya data apa yang disimpan dan berapa kerugian jika layanan mati sehari. Indeks kesehatan adalah indikator kasar untuk membandingkan dari waktu ke waktu, bukan standar baku atau sertifikasi kepatuhan.
- **Estimasi jam adalah perkiraan umum** untuk satu engineer, belum termasuk koordinasi, pengujian di lingkungan klien, dan jendela perawatan.
- **Tanggal akhir dukungan OS** ada di tabel di [`audit/rules.py`](audit/rules.py) dan merupakan perkiraan. Verifikasi ke situs vendor sebelum dijadikan dasar keputusan.
- **Kolektor mengirim beberapa request HTTP ke web server di server itu sendiri** (HEAD ke halaman utama, dan satu GET per file sensitif yang ditemukan; isinya dibuang). Aman untuk produksi, tapi akan muncul di log akses.
- Diuji pada satu jenis server di lab. Server dengan konfigurasi yang sangat berbeda bisa memunculkan false positive atau negatif yang belum ditemukan, jadi hasil audit pertama di server klien baru sebaiknya ditinjau manual.

## Struktur

```
collect.py            kolektor fakta (hanya baca), dijalankan di server
audit/rules.py        28 aturan: bukti, dampak, rekomendasi, estimasi jam
audit/report.py       diagram arsitektur, indeks, perbandingan, render Markdown/HTML
tests/                16 uji dengan fakta sintetis
tools/                uji mutasi
test/                 lab: VM + server rentan + hardening + audit ulang
results/              laporan contoh, fakta mentah, hasil tes
```

`test/harden.sh` dan `test/harden-web.sh` adalah salinan dari project hardening OS dan hardening web, dipakai untuk tahap perbaikan di lab.
