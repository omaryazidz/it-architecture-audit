"""Menyusun laporan audit (Markdown dan HTML mandiri) dari fakta server."""
import html
from collections import Counter

from .rules import SEVERITIES, evaluate, public_ports, has_firewall

PENALTY = {"Tinggi": 10, "Sedang": 4, "Rendah": 1}
ROADMAP = {"Tinggi": "Minggu ini (0-7 hari)", "Sedang": "Bulan ini (≤ 30 hari)", "Rendah": "Kuartal ini (≤ 90 hari)"}


def risk_index(findings):
    """100 dikurangi bobot temuan (Tinggi 10, Sedang 4, Rendah 1), minimum 0. Indikator kasar, bukan standar baku."""
    return max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))


def architecture(facts):
    """Diagram teks arsitektur dari fakta: port publik, firewall, dan komponen yang berjalan."""
    run = " ".join(facts["services"]["running"])
    web = "Nginx" if facts["web"]["nginx"] else "Apache" if facts["web"]["apache"] else None
    app = "PHP-FPM" if "php" in run and "fpm" in run else None
    db = "MariaDB/MySQL" if facts["database"]["mysql"] else "PostgreSQL" if facts["database"]["postgresql"] else None
    ports = ", ".join(map(str, public_ports(facts))) or "tidak ada"
    fw = "aktif" if has_firewall(facts) else "TIDAK ADA"
    chain = " ──► ".join(f"[{c}]" for c in (web, app, db) if c) or "[layanan tidak dikenali]"
    return "\n".join([
        "Internet",
        f"   │  port TCP terbuka ke publik: {ports}",
        f"   ▼  firewall: {fw}",
        f"{chain}",
        f"   server tunggal: {facts['system']['os']}, {facts['system']['cpus']} vCPU, {facts['system']['memory_mb']} MB RAM",
    ])


def build(facts, client, before=None):
    findings, good = evaluate(facts)
    r = {"client": client, "host": facts["system"]["hostname"], "os": facts["system"]["os"],
         "collected_at": facts["collected_at"], "findings": findings, "good": good,
         "counts": Counter(f["severity"] for f in findings), "index": risk_index(findings),
         "hours": sum(f["hours"] for f in findings), "arch": architecture(facts), "compare": None}
    if before:
        bf, _ = evaluate(before)
        b_ids, a_ids = {f["id"] for f in bf}, {f["id"] for f in findings}
        r["compare"] = {"before_index": risk_index(bf), "before_total": len(bf),
                        "resolved": [f for f in bf if f["id"] not in a_ids],
                        "remaining": [f for f in findings if f["id"] in b_ids],
                        "new": [f for f in findings if f["id"] not in b_ids],
                        "before_counts": Counter(f["severity"] for f in bf)}
    return r


def to_markdown(r):
    c = r["counts"]
    L = [f"# Laporan Audit Arsitektur IT: {r['client']}", "",
         f"- Server: `{r['host']}` ({r['os']})",
         f"- Data dikumpulkan: {r['collected_at']} (hanya baca, tidak ada perubahan ke server)", "",
         "## 1. Ringkasan eksekutif", "",
         f"**Temuan: {len(r['findings'])}** (Tinggi {c['Tinggi']}, Sedang {c['Sedang']}, Rendah {c['Rendah']}). "
         f"Indeks kesehatan **{r['index']}/100**. Estimasi pengerjaan seluruh temuan: **±{r['hours']:g} jam kerja**.", ""]
    if r["compare"]:
        k = r["compare"]
        L += [f"**Dibanding audit sebelumnya:** indeks {k['before_index']} → {r['index']}, "
              f"temuan {k['before_total']} → {len(r['findings'])}; "
              f"{len(k['resolved'])} selesai, {len(k['remaining'])} masih ada, {len(k['new'])} baru.", ""]
    L += ["> Indeks = 100 dikurangi bobot temuan (Tinggi 10, Sedang 4, Rendah 1). Ini indikator kasar untuk membandingkan "
          "dari waktu ke waktu, bukan standar baku.", "",
          "## 2. Gambaran arsitektur saat ini", "", "```", r["arch"], "```", "",
          "## 3. Temuan", ""]
    for sev in SEVERITIES:
        items = [f for f in r["findings"] if f["severity"] == sev]
        if not items:
            continue
        L += [f"### Prioritas {sev} ({len(items)})", ""]
        for f in items:
            L += [f"**{f['id']} · {f['title']}** ({f['category']}, ±{f['hours']:g} jam)", "",
                  f"- Bukti: {f['evidence']}", f"- Dampak: {f['impact']}", f"- Rekomendasi: {f['fix']}", ""]
    if not r["findings"]:
        L += ["Tidak ada temuan pada aturan yang diperiksa.", ""]
    L += ["## 4. Rencana perbaikan", ""]
    for sev in SEVERITIES:
        items = [f for f in r["findings"] if f["severity"] == sev]
        if items:
            L += [f"**{ROADMAP[sev]}**: ±{sum(f['hours'] for f in items):g} jam", ""] + [f"- {f['id']} {f['title']}" for f in items] + [""]
    if r["compare"]:
        L += ["## 5. Perubahan sejak audit sebelumnya", ""]
        for title, key in (("Sudah selesai", "resolved"), ("Masih ada", "remaining"), ("Temuan baru", "new")):
            items = r["compare"][key]
            L += [f"**{title} ({len(items)})**", ""] + ([f"- {f['id']} {f['title']} ({f['severity']})" for f in items] or ["- tidak ada"]) + [""]
    L += [f"## {6 if r['compare'] else 5}. Yang sudah baik", ""] + [f"- {g}" for g in r["good"]] + [""]
    L += ["## Batasan audit", "",
          "- Audit ini memeriksa kondisi teknis server pada saat pengumpulan data. Tidak mencakup kode aplikasi, proses bisnis, "
          "kepatuhan hukum, atau infrastruktur di luar server ini.",
          "- Temuan berbasis aturan baku. Prioritas akhir tetap perlu disesuaikan dengan konteks bisnis (mis. data apa yang disimpan, "
          "berapa biaya jika layanan mati sehari).",
          "- Estimasi jam adalah perkiraan kerja satu engineer, belum termasuk koordinasi, pengujian di lingkungan klien, dan jendela perawatan.", ""]
    return "\n".join(L)


CSS = """body{font:16px/1.55 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1c1f23}
h1{font-size:1.7rem}h2{margin-top:2.2rem;border-bottom:2px solid #e3e6ea;padding-bottom:.3rem}
pre{background:#f4f6f8;padding:1rem;overflow:auto;border-radius:6px;font-size:.9rem}
.f{border:1px solid #e3e6ea;border-left-width:6px;border-radius:6px;padding:.7rem 1rem;margin:.8rem 0}
.Tinggi{border-left-color:#c0392b}.Sedang{border-left-color:#d68910}.Rendah{border-left-color:#2e86c1}
.b{display:inline-block;padding:.05rem .55rem;border-radius:99px;color:#fff;font-size:.8rem;margin-right:.4rem}
.b.Tinggi{background:#c0392b}.b.Sedang{background:#d68910}.b.Rendah{background:#2e86c1}
.kpi{display:flex;gap:1rem;flex-wrap:wrap}.kpi div{flex:1;min-width:140px;background:#f4f6f8;padding:.8rem;border-radius:6px}
.kpi b{font-size:1.6rem;display:block}.muted{color:#5d6670;font-size:.9rem}li{margin:.2rem 0}
@media print{body{max-width:none;margin:0}.f{break-inside:avoid}}"""


def to_html(r):
    e = html.escape
    c = r["counts"]
    out = [f"<!doctype html><html lang='id'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>Laporan Audit {e(r['client'])}</title><style>{CSS}</style><body>",
           f"<h1>Laporan Audit Arsitektur IT<br><small>{e(r['client'])}</small></h1>",
           f"<p class='muted'>Server <code>{e(r['host'])}</code> · {e(r['os'])} · data dikumpulkan {e(r['collected_at'])} (hanya baca)</p>",
           "<h2>1. Ringkasan eksekutif</h2><div class='kpi'>"
           f"<div><b>{r['index']}/100</b>indeks kesehatan</div><div><b>{len(r['findings'])}</b>temuan</div>"
           f"<div><b>{c['Tinggi']} / {c['Sedang']} / {c['Rendah']}</b>tinggi / sedang / rendah</div>"
           f"<div><b>±{r['hours']:g} jam</b>estimasi pengerjaan</div></div>"]
    if r["compare"]:
        k = r["compare"]
        out.append(f"<p><b>Dibanding audit sebelumnya:</b> indeks {k['before_index']} → <b>{r['index']}</b>, temuan {k['before_total']} → "
                   f"<b>{len(r['findings'])}</b>; {len(k['resolved'])} selesai, {len(k['remaining'])} masih ada, {len(k['new'])} baru.</p>")
    out += ["<p class='muted'>Indeks = 100 dikurangi bobot temuan (Tinggi 10, Sedang 4, Rendah 1). Indikator kasar untuk membandingkan "
            "dari waktu ke waktu, bukan standar baku.</p>",
            f"<h2>2. Gambaran arsitektur saat ini</h2><pre>{e(r['arch'])}</pre><h2>3. Temuan</h2>"]
    for f in r["findings"]:
        out.append(f"<div class='f {f['severity']}'><span class='b {f['severity']}'>{f['severity']}</span><b>{e(f['id'])} · {e(f['title'])}</b> "
                   f"<span class='muted'>({e(f['category'])}, ±{f['hours']:g} jam)</span>"
                   f"<ul><li><b>Bukti:</b> {e(f['evidence'])}</li><li><b>Dampak:</b> {e(f['impact'])}</li>"
                   f"<li><b>Rekomendasi:</b> {e(f['fix'])}</li></ul></div>")
    if not r["findings"]:
        out.append("<p>Tidak ada temuan pada aturan yang diperiksa.</p>")
    out.append("<h2>4. Rencana perbaikan</h2>")
    for sev in SEVERITIES:
        items = [f for f in r["findings"] if f["severity"] == sev]
        if items:
            out.append(f"<p><b>{e(ROADMAP[sev])}</b>: ±{sum(f['hours'] for f in items):g} jam</p><ul>" +
                       "".join(f"<li>{e(f['id'])} {e(f['title'])}</li>" for f in items) + "</ul>")
    n = 5
    if r["compare"]:
        out.append("<h2>5. Perubahan sejak audit sebelumnya</h2>")
        for title, key in (("Sudah selesai", "resolved"), ("Masih ada", "remaining"), ("Temuan baru", "new")):
            items = r["compare"][key]
            out.append(f"<p><b>{title} ({len(items)})</b></p><ul>" + ("".join(f"<li>{e(f['id'])} {e(f['title'])} ({f['severity']})</li>" for f in items) or "<li>tidak ada</li>") + "</ul>")
        n = 6
    out.append(f"<h2>{n}. Yang sudah baik</h2><ul>" + "".join(f"<li>{e(g)}</li>" for g in r["good"]) + "</ul>")
    out.append("<h2>Batasan audit</h2><ul><li>Memeriksa kondisi teknis server saat pengumpulan data. Tidak mencakup kode aplikasi, proses bisnis, "
               "kepatuhan hukum, atau infrastruktur di luar server ini.</li><li>Temuan berbasis aturan baku; prioritas akhir perlu disesuaikan "
               "dengan konteks bisnis.</li><li>Estimasi jam adalah perkiraan kerja satu engineer, belum termasuk koordinasi, pengujian di "
               "lingkungan klien, dan jendela perawatan.</li></ul></body></html>")
    return "".join(out)
