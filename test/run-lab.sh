#!/usr/bin/env bash
# Audit nyata: VM baru -> server WordPress yang belum diamankan -> kumpulkan fakta -> laporan.
# Lalu hardening (harden.sh dan harden-web.sh dari project lain) -> audit ulang -> laporan perbandingan.
# Jalankan di lab WSL:  sudo bash test/run-lab.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
mkdir -p results
KEY=/root/weblab/lab_key
SSHO=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
vm() { ssh -tt -q "${SSHO[@]}" -p 2223 sysadmin@127.0.0.1 "$@"; }
CLIENT="Toko Demo (server lab, fiktif)"
step() { echo; echo "##### $* #####"; }

step "0. MENYIAPKAN SERVER KLIEN FIKTIF (WordPress + Nginx + MariaDB, konfigurasi bawaan)"
bash test/lab-vm.sh down
bash test/lab-vm.sh up || exit 1
scp -q "${SSHO[@]}" -P 2223 collect.py test/setup-vulnerable.sh test/harden.sh test/harden-web.sh sysadmin@127.0.0.1:
vm 'sudo bash setup-vulnerable.sh' >/dev/null 2>&1 || { echo "setup gagal"; exit 1; }

step "1. AUDIT PERTAMA: kumpulkan fakta (hanya baca) dan buat laporan"
vm 'sudo python3 collect.py' | tr -d '\r' >results/facts-before.json
python3 -m audit results/facts-before.json --client "$CLIENT" --out results/audit-awal

step "2. PERBAIKAN: hardening OS dan web server (toolkit #1 dan #1b)"
vm 'sudo ALLOW_PORTS="80,443" bash harden.sh apply 2>&1 | tail -3; sudo bash harden-web.sh apply 2>&1 | tail -3'

step "3. AUDIT ULANG: bandingkan dengan audit pertama"
vm 'sudo python3 collect.py' | tr -d '\r' >results/facts-after.json
python3 -m audit results/facts-after.json --before results/facts-before.json --client "$CLIENT" --out results/audit-ulang
