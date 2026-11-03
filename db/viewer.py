"""
Visor web de la BBDD, SOLO LECTURA, para revisar tablas y vistas desde el navegador.
Uso (desde la raíz del repo):
    .venv/bin/python db/viewer.py          -> http://127.0.0.1:8765
Escucha solo en localhost. Todas las consultas van en transacción read-only con timeout.
"""
import html
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import psycopg
from psycopg import sql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

HOST, PORT = "127.0.0.1", int(os.environ.get("VIEWER_PORT", "8765"))
PAGE = 100
MAX_ROWS = 500

CSS = """
:root { --bg:#0f1115; --panel:#171a21; --line:#2a2f3a; --text:#e6e8ec; --muted:#9aa3b2; --accent:#4f8cff; }
* { box-sizing:border-box; }
body { margin:0; font:14px/1.45 system-ui, sans-serif; background:var(--bg); color:var(--text); display:flex; min-height:100vh; }
nav { width:260px; flex-shrink:0; background:var(--panel); border-right:1px solid var(--line); padding:16px; overflow:auto; }
nav h1 { font-size:16px; margin:0 0 12px; }
nav h2 { font-size:12px; text-transform:uppercase; color:var(--muted); margin:16px 0 6px; letter-spacing:.05em; }
nav a { display:flex; justify-content:space-between; color:var(--text); text-decoration:none; padding:4px 8px; border-radius:6px; }
nav a:hover, nav a.on { background:#232836; }
nav a span { color:var(--muted); font-variant-numeric:tabular-nums; }
main { flex:1; padding:20px; overflow:auto; min-width:0; }
h3 { margin:0 0 4px; } .muted { color:var(--muted); }
table { border-collapse:collapse; margin-top:12px; font-size:13px; }
th, td { border:1px solid var(--line); padding:4px 8px; text-align:left; vertical-align:top; max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
th { background:var(--panel); position:sticky; top:0; }
td.null { color:var(--muted); font-style:italic; }
textarea { width:100%; min-height:90px; background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:8px; font:13px ui-monospace, monospace; }
button, .btn { background:var(--accent); color:#fff; border:0; border-radius:6px; padding:6px 14px; cursor:pointer; text-decoration:none; display:inline-block; margin-top:8px; }
.err { background:#3a1c1c; border:1px solid #7a2e2e; padding:8px 12px; border-radius:6px; margin-top:12px; white-space:pre-wrap; }
.pager { margin-top:10px; display:flex; gap:8px; align-items:center; }
"""


def connect():
    conn = psycopg.connect(sslmode="require", connect_timeout=15, options="-c statement_timeout=15000")
    conn.read_only = True  # cada transacción se abre como READ ONLY
    return conn


def relations(conn):
    rows = conn.execute(
        """SELECT c.relname, c.relkind, c.reltuples::bigint
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relkind IN ('r','v')
           ORDER BY c.relkind, c.relname"""
    ).fetchall()
    out = []
    for name, kind, _ in rows:
        n = conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(name))).fetchone()[0]
        out.append((name, kind, n))
    return out


def cell(v):
    if v is None:
        return '<td class="null">null</td>'
    s = str(v)
    return f'<td title="{html.escape(s[:2000])}">{html.escape(s[:300])}</td>'


def table_html(cols, rows):
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(cell(v) for v in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def page(nav, content):
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>BBDD Equipo 2</title>
<style>{CSS}</style></head><body><nav>{nav}</nav><main>{content}</main></body></html>"""


def nav_html(rels, current):
    parts = ["<h1>BBDD Equipo 2</h1>", '<a href="/sql">Consulta SQL</a>']
    for kind, title in (("r", "Tablas"), ("v", "Vistas")):
        parts.append(f"<h2>{title}</h2>")
        for name, k, n in rels:
            if k == kind:
                on = ' class="on"' if name == current else ""
                parts.append(f'<a{on} href="/?{urlencode({"t": name})}">{html.escape(name)} <span>{n}</span></a>')
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/sql":
            return self.render_sql("SELECT * FROM v_kpis;")
        if url.path != "/":
            return self.send("No encontrado", 404)
        with connect() as conn:
            rels = relations(conn)
            names = {r[0] for r in rels}
            t = q.get("t", ["v_kpis"])[0]
            if t not in names:
                t = "v_kpis"
            offset = max(int(q.get("o", ["0"])[0] or 0), 0)
            total = next(n for name, _, n in rels if name == t)
            cur = conn.execute(
                sql.SQL("SELECT * FROM {} LIMIT %s OFFSET %s").format(sql.Identifier(t)), (PAGE, offset)
            )
            cols = [d.name for d in cur.description]
            rows = cur.fetchall()
        pager = ""
        if total > PAGE:
            prev_o, next_o = max(offset - PAGE, 0), offset + PAGE
            prev_l = f'<a class="btn" href="/?{urlencode({"t": t, "o": prev_o})}">← Anterior</a>' if offset else ""
            next_l = f'<a class="btn" href="/?{urlencode({"t": t, "o": next_o})}">Siguiente →</a>' if next_o < total else ""
            pager = f'<div class="pager">{prev_l}<span class="muted">{offset + 1}–{min(offset + PAGE, total)} de {total}</span>{next_l}</div>'
        content = (f"<h3>{html.escape(t)}</h3><div class='muted'>{total} filas · {len(cols)} columnas</div>"
                   f"{pager}{table_html(cols, rows)}")
        self.send(page(nav_html(rels, t), content))

    def do_POST(self):
        if urlparse(self.path).path != "/sql":
            return self.send("No encontrado", 404)
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        self.render_sql(form.get("q", [""])[0])

    def render_sql(self, query):
        result = ""
        with connect() as conn:
            rels = relations(conn)
            if query.strip():
                try:
                    cur = conn.execute(query)
                    if cur.description:
                        cols = [d.name for d in cur.description]
                        rows = cur.fetchmany(MAX_ROWS)
                        result = f"<div class='muted'>{len(rows)} filas (máx. {MAX_ROWS})</div>{table_html(cols, rows)}"
                    else:
                        result = "<div class='muted'>Sin resultados.</div>"
                except Exception as e:
                    result = f"<div class='err'>{html.escape(str(e))}</div>"
                finally:
                    conn.rollback()
        content = (f"<h3>Consulta SQL</h3><div class='muted'>Solo lectura · timeout 15 s</div>"
                   f"<form method='post' action='/sql'><textarea name='q'>{html.escape(query)}</textarea>"
                   f"<button>Ejecutar</button></form>{result}")
        self.send(page(nav_html(rels, None), content))


if __name__ == "__main__":
    print(f"Visor en http://{HOST}:{PORT} (solo lectura). Ctrl+C para parar.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
