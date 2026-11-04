"""
Genera los entregables en PDF con Chromium sin interfaz (no hace falta pandoc ni LaTeX).

    Informe_Equipo2.pdf               ← docs/informe/INFORME.md (portada + A4 vertical)
    Diapositivas_Equipo2.pdf          ← docs/entrega/diapositivas.html (8 páginas 16:9)
    Infografia_BD.pdf                 ← docs/infografias/bbdd_equipo2.html      (póster de 1 página, tema claro)
    Infografia_Cadena_Moreno.pdf      ← docs/infografias/cadena_moreno.html     (póster de 1 página, tema claro)
    Infografia_Informe.pdf            ← docs/infografias/informe_final.html     (póster de 1 página, tema claro)

Uso (desde la raíz del repo, tras regenerar informe e infografías):
    .venv/bin/python docs/entrega/generar_pdfs.py [--copia "/ruta/a/carpeta"]
"""
import argparse
import html
import shutil
import subprocess
import tempfile
from pathlib import Path

import markdown

DIR = Path(__file__).resolve().parent
ROOT = DIR.parent.parent
CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")

# Infografías: tema claro, <details> abiertos y una sola página tan alta como el contenido (formato póster)
TEMA_CLARO = ('<script>document.documentElement.setAttribute("data-theme","light");'
              'addEventListener("load",()=>{document.querySelectorAll("details").forEach(d=>d.open=true);'
              'document.fonts.ready.then(()=>{const h=Math.ceil(Math.max(document.documentElement.scrollHeight,'
              'document.body.scrollHeight)*1.05)+120;const st=document.createElement("style");'
              'st.textContent="@page{size:1280px "+h+"px;margin:0}";document.head.appendChild(st);});})</script>')

CSS_INFORME = """
@page{size:A4;margin:16mm 15mm 18mm}
@page{@bottom-right{content:"Equipo 2 · Informe final · " counter(page) " / " counter(pages);
  font:8.5pt 'JetBrains Mono',monospace;color:#7a8494}}
@page:first{@bottom-right{content:none}}
*{box-sizing:border-box}
body{font:10.2pt/1.5 'Public Sans',system-ui,sans-serif;color:#151a22;margin:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
h1,h2,h3{font-family:'Archivo Narrow','Arial Narrow',sans-serif;line-height:1.15;break-after:avoid}
h1{font-size:24pt;margin:0 0 6pt} h2{font-size:17pt;margin:18pt 0 6pt;padding-top:6pt;border-top:2px solid #2F68C2}
h3{font-size:12.5pt;margin:12pt 0 4pt}
p,li{orphans:3;widows:3} ul{padding-left:16pt} li{margin:2pt 0}
code{font:8.8pt 'JetBrains Mono',monospace;background:#eef2f4;padding:0 3pt;border-radius:2pt}
table{border-collapse:collapse;width:100%;font-size:8.4pt;margin:6pt 0;break-inside:auto}
tr{break-inside:avoid} th,td{border-bottom:1px solid #dde2ea;padding:3pt 5pt;text-align:left;vertical-align:top}
th{background:#eef2f4;font-weight:600}
em{color:#4a5463}
.cover{height:245mm;display:flex;flex-direction:column;justify-content:center;gap:14pt;break-after:page}
.cover .eyebrow{font:9pt 'JetBrains Mono',monospace;letter-spacing:.08em;text-transform:uppercase;color:#2F68C2}
.cover h1{font-size:40pt;line-height:1}
.cover .bar{display:flex;gap:3pt;width:70mm;height:6pt}.cover .bar i{flex:1;border-radius:1pt}
.cover p{font-size:12pt;color:#4a5463;max-width:150mm;margin:0}
.cover dl{display:grid;grid-template-columns:42mm 1fr;gap:4pt 10pt;font-size:10pt;margin-top:18pt}
.cover dt{color:#7a8494}.cover dd{margin:0}
"""


def pdf(origen: Path, destino: Path) -> None:
    subprocess.run([CHROMIUM, "--headless", "--disable-gpu", "--no-pdf-header-footer", "--virtual-time-budget=6000",
                    "--window-size=1280,900",
                    f"--print-to-pdf={destino}", origen.as_uri()],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    print(f"{destino.name}: {destino.stat().st_size // 1024} KB")


def informe_html(tmp: Path) -> Path:
    md = (ROOT / "docs/informe/INFORME.md").read_text(encoding="utf-8")
    titulo, _, cuerpo = md.partition("\n")
    generado = next((l for l in cuerpo.splitlines() if l.startswith("*Generado")), "").strip("*")
    cuerpo = cuerpo.replace(f"*{generado}*", "", 1)
    contenido = markdown.markdown(cuerpo, extensions=["tables", "sane_lists"])
    portada = f"""
<section class="cover">
  <div class="eyebrow">Hackathon FP Sampol · Reto SOC · Equipo 2</div>
  <div class="bar"><i style="background:#2F68C2"></i><i style="background:#B57A06"></i><i style="background:#B0306E"></i></div>
  <h1>Informe final del incidente<br>y de la solución SOC</h1>
  <p>Qué ha pasado, cuánto puede costar a la empresa, qué hemos construido y qué recomendamos.
     Cada cifra indica su origen: [D] dato del director, [BD] base de datos del equipo, [H] hipótesis del equipo.</p>
  <dl>
    <dt>Fecha</dt><dd>{html.escape(generado.replace('Generado el ', '').split(' a partir')[0])}</dd>
    <dt>Equipo</dt><dd>Equipo 2 (5 personas)</dd>
    <dt>Anexos</dt><dd>A · Evidencias del buzón · B · Metodología y fuentes</dd>
    <dt>Material adjunto</dt><dd>Diapositivas e infografías de la base de datos, de la cadena Moreno y del informe (PDF)</dd>
  </dl>
</section>"""
    doc = (f'<!doctype html><html lang="es"><head><meta charset="utf-8"><title>{html.escape(titulo.lstrip("# "))}</title>'
           '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo+Narrow:wght@600;700'
           '&family=Public+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap">'
           f"<style>{CSS_INFORME}</style></head><body>{portada}{contenido}</body></html>")
    destino = tmp / "informe.html"
    destino.write_text(doc, encoding="utf-8")
    return destino


def infografia(origen: Path, tmp: Path) -> Path:
    destino = tmp / origen.name
    destino.write_text(TEMA_CLARO + origen.read_text(encoding="utf-8"), encoding="utf-8")
    return destino


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--copia", help="carpeta adicional donde copiar los PDF")
    a = p.parse_args()
    if not CHROMIUM:
        raise SystemExit("No se encuentra Chromium.")
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        salidas = [DIR / "Informe_Equipo2.pdf", DIR / "Diapositivas_Equipo2.pdf", DIR / "Infografia_BD.pdf",
                   DIR / "Infografia_Cadena_Moreno.pdf", DIR / "Infografia_Informe.pdf"]
        pdf(informe_html(tmp), salidas[0])
        pdf(DIR / "diapositivas.html", salidas[1])
        inf = ROOT / "docs/infografias"
        pdf(infografia(inf / "bbdd_equipo2.html", tmp), salidas[2])
        pdf(infografia(inf / "cadena_moreno.html", tmp), salidas[3])
        pdf(infografia(inf / "informe_final.html", tmp), salidas[4])
    if a.copia:
        copia = Path(a.copia)
        copia.mkdir(parents=True, exist_ok=True)
        for s in salidas:
            shutil.copy2(s, copia / s.name)
        shutil.copy2(DIR / "GUION_presentacion.md", copia / "GUION_presentacion.md")
        print(f"Copiados en {copia}")


if __name__ == "__main__":
    main()
