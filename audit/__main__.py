"""CLI: python -m audit facts.json --client "Nama Klien" --out laporan [--before facts-lama.json]"""
import argparse
import json
from pathlib import Path

from .report import build, to_html, to_markdown


def main(argv=None):
    p = argparse.ArgumentParser(description="Buat laporan audit dari fakta hasil collect.py")
    p.add_argument("facts")
    p.add_argument("--client", default="Klien")
    p.add_argument("--out", required=True, help="awalan berkas keluaran (menghasilkan .md dan .html)")
    p.add_argument("--before", help="fakta audit sebelumnya, untuk laporan perbandingan")
    a = p.parse_args(argv)
    load = lambda f: json.loads(Path(f).read_text(encoding="utf-8"))
    r = build(load(a.facts), a.client, load(a.before) if a.before else None)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".md").write_text(to_markdown(r), encoding="utf-8")
    out.with_suffix(".html").write_text(to_html(r), encoding="utf-8")
    c = r["counts"]
    print(f"{out}.md / .html  |  temuan {len(r['findings'])} (Tinggi {c['Tinggi']}, Sedang {c['Sedang']}, Rendah {c['Rendah']})  "
          f"indeks {r['index']}/100  estimasi ±{r['hours']:g} jam")


if __name__ == "__main__":
    main()
