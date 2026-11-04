"""
Bloqueador SIMULADO del Equipo 2: imita el contrato OpenAPI de la API de bloqueo del reto para enseñar la contención de
principio a fin mientras la clave real está revocada (401). NO bloquea nada real.

- Solo escucha en 127.0.0.1. Clave de demostración: SIMULADOR_API_KEY (por defecto "demo-local"; no es un secreto).
- Mismos endpoints, códigos y esquemas que la API real:
    POST /equipo-2/bloquear  {"ip"|"usuario"} -> 201 Resultado
    POST /equipo-2/liberar   {"ip"|"usuario"} -> 200 Resultado
    GET  /equipo-2/bloqueos?activo&tipo&limit&offset -> 200 [BloqueoSalida]
  Sin clave o con clave incorrecta -> 401 {"detail": "Contraseña de equipo incorrecta o ausente."}
- Todas las respuestas llevan "simulacion": true y la cabecera X-Simulacion: 1.
- GET / -> página con los bloqueos y un botón «Liberar» (liberación en un clic para la demostración).

Uso (desde la raíz del repo):  .venv/bin/python demo/bloqueador_simulado.py   ->  http://127.0.0.1:8090
"""
import html
import ipaddress
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
ESTADO = ROOT / "data" / "simulador_bloqueos.json"
CLAVE = os.getenv("SIMULADOR_API_KEY", "demo-local")
PUERTO = int(os.getenv("SIMULADOR_PUERTO", "8090"))
EQUIPO = 2
ERROR_401 = {"detail": "Contraseña de equipo incorrecta o ausente."}
LOCK = threading.Lock()


def ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


def cargar() -> dict:
    try:
        return json.loads(ESTADO.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"siguiente_bloqueo": 1, "siguiente_accion": 1, "bloqueos": []}


def guardar(estado: dict) -> None:
    ESTADO.parent.mkdir(parents=True, exist_ok=True)
    tmp = ESTADO.with_suffix(".tmp")
    tmp.write_text(json.dumps(estado, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(ESTADO)


def error_422(campo: str, mensaje: str) -> dict:
    return {"detail": [{"loc": ["body", campo], "msg": mensaje, "type": "value_error"}]}


def objetivo(cuerpo) -> tuple[str, str] | dict:
    """Valida el body Objetivo: exactamente uno de ip / usuario (como la API real)."""
    if not isinstance(cuerpo, dict) or set(cuerpo) - {"ip", "usuario"}:
        return error_422("objetivo", "Solo se admiten los campos ip o usuario")
    ip, usuario = cuerpo.get("ip"), cuerpo.get("usuario")
    if (ip is None) == (usuario is None):
        return error_422("objetivo", "Indique exactamente uno: ip o usuario")
    if ip is not None:
        try:
            return "ip", str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return error_422("ip", "Dirección IP no válida")
    usuario = str(usuario).strip()
    if not 1 <= len(usuario) <= 255:
        return error_422("usuario", "Longitud de usuario no válida")
    return "usuario", usuario


class Manejador(BaseHTTPRequestHandler):
    server_version = "BloqueadorSimulado/1.0"

    def log_message(self, formato, *args):
        print(f"[SIMULADOR] {self.address_string()} {formato % args}")

    def responder(self, codigo: int, datos, tipo="application/json"):
        cuerpo = datos if isinstance(datos, (bytes, str)) else json.dumps(datos, ensure_ascii=False)
        cuerpo = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo
        self.send_response(codigo)
        self.send_header("Content-Type", f"{tipo}; charset=utf-8")
        self.send_header("X-Simulacion", "1")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def autorizado(self) -> bool:
        if self.headers.get("X-API-Key") != CLAVE:
            self.responder(401, ERROR_401)
            return False
        return True

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            return self.pagina()
        if url.path != f"/equipo-{EQUIPO}/bloqueos":
            return self.responder(404, {"detail": "Not Found"})
        if not self.autorizado():
            return
        q = parse_qs(url.query)
        try:
            limit = int(q.get("limit", ["100"])[0])
            offset = int(q.get("offset", ["0"])[0])
            assert 1 <= limit <= 100 and offset >= 0
        except (ValueError, AssertionError):
            return self.responder(422, error_422("limit", "limit 1-100 y offset >= 0"))
        activo = q.get("activo", [None])[0]
        tipo = q.get("tipo", [None])[0]
        if tipo not in (None, "ip", "usuario"):
            return self.responder(422, error_422("tipo", "tipo debe ser ip o usuario"))
        with LOCK:
            filas = cargar()["bloqueos"]
        if activo is not None:
            filas = [b for b in filas if b["activo"] == (activo.lower() == "true")]
        if tipo:
            filas = [b for b in filas if b["tipo"] == tipo]
        self.responder(200, [dict(b, simulacion=True) for b in filas[offset:offset + limit]])

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/ui/liberar":
            return self.liberar_desde_pagina()
        accion = {f"/equipo-{EQUIPO}/bloquear": "bloquear", f"/equipo-{EQUIPO}/liberar": "liberar"}.get(url.path)
        if accion is None:
            return self.responder(404, {"detail": "Not Found"})
        if not self.autorizado():
            return
        try:
            cuerpo = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"null")
        except json.JSONDecodeError:
            return self.responder(422, error_422("body", "JSON no válido"))
        obj = objetivo(cuerpo)
        if isinstance(obj, dict):
            return self.responder(422, obj)
        codigo, resultado = operar(accion, *obj)
        self.responder(codigo, resultado)

    def liberar_desde_pagina(self):
        datos = parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8"))
        tipo, valor = datos.get("tipo", [""])[0], datos.get("valor", [""])[0]
        if tipo in ("ip", "usuario") and valor:
            operar("liberar", tipo, valor)
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def pagina(self):
        with LOCK:
            filas = cargar()["bloqueos"]
        cuerpo = "".join(
            f"<tr><td>{b['id']}</td><td>{html.escape(b['tipo'])}</td><td><b>{html.escape(b['valor'])}</b></td>"
            f"<td>{'<span class=on>BLOQUEADO</span>' if b['activo'] else 'liberado'}</td>"
            f"<td>{html.escape(b['bloqueado_en'][:19].replace('T', ' '))}</td>"
            f"<td>{html.escape((b['liberado_en'] or '')[:19].replace('T', ' '))}</td>"
            f"<td>{len(b['acciones'])}</td><td>"
            + (f"<form method=post action=/ui/liberar><input type=hidden name=tipo value='{html.escape(b['tipo'])}'>"
               f"<input type=hidden name=valor value='{html.escape(b['valor'])}'><button>Liberar</button></form>"
               if b["activo"] else "") + "</td></tr>"
            for b in sorted(filas, key=lambda x: x["id"]))
        activos = sum(1 for b in filas if b["activo"])
        self.responder(200, f"""<!doctype html><html lang=es><meta charset=utf-8><meta http-equiv=refresh content=10>
<title>Bloqueador simulado · Equipo 2</title>
<style>body{{font:15px system-ui,sans-serif;margin:24px;color:#151a22;background:#f6f7f9}}
.aviso{{background:#fff4e0;border:1px solid #f0c879;color:#7a4b00;padding:10px 14px;border-radius:6px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%;background:#fff}}td,th{{padding:6px 8px;border-bottom:1px solid #dde2ea;text-align:left}}
.on{{color:#B0306E;font-weight:600}}button{{cursor:pointer}}</style>
<div class=aviso><b>SIMULACIÓN.</b> Bloqueador local que imita la API del reto (mismo contrato). No bloquea nada real:
la clave real está revocada (401) y la cola real sigue esperando en la base de datos.</div>
<h1>Bloqueos simulados · {activos} activos de {len(filas)}</h1>
<table><tr><th>ID</th><th>Tipo</th><th>Objetivo</th><th>Estado</th><th>Bloqueado (UTC)</th><th>Liberado (UTC)</th><th>Acciones</th><th></th></tr>
{cuerpo}</table>""", "text/html")


def operar(accion: str, tipo: str, valor: str) -> tuple[int, dict]:
    """Bloquea o libera en el estado simulado. Devuelve (código HTTP, Resultado)."""
    with LOCK:
        estado = cargar()
        bloqueo = next((b for b in estado["bloqueos"]
                        if b["tipo"] == tipo and b["valor"].lower() == valor.lower()), None)
        if accion == "bloquear":
            if bloqueo and bloqueo["activo"]:
                return 201, {"mensaje": "El objetivo ya estaba bloqueado (simulación)", "bloqueo": bloqueo, "simulacion": True}
            if bloqueo is None:
                bloqueo = {"id": estado["siguiente_bloqueo"], "equipo_id": EQUIPO, "tipo": tipo, "valor": valor,
                           "activo": True, "creado_en": ahora(), "bloqueado_en": ahora(), "liberado_en": None, "acciones": []}
                estado["siguiente_bloqueo"] += 1
                estado["bloqueos"].append(bloqueo)
            else:
                bloqueo.update(activo=True, bloqueado_en=ahora(), liberado_en=None)
            mensaje, codigo = "Bloqueo registrado (simulación)", 201
        else:
            if not bloqueo or not bloqueo["activo"]:
                return 200, {"mensaje": "El objetivo no estaba bloqueado (simulación)",
                             "bloqueo": bloqueo or {"id": 0, "equipo_id": EQUIPO, "tipo": tipo, "valor": valor,
                                                    "activo": False, "creado_en": ahora(), "bloqueado_en": ahora(),
                                                    "liberado_en": ahora(), "acciones": []},
                             "simulacion": True}
            bloqueo.update(activo=False, liberado_en=ahora())
            mensaje, codigo = "Bloqueo liberado (simulación)", 200
        bloqueo["acciones"].append({"id": estado["siguiente_accion"], "equipo_id": EQUIPO, "accion": accion, "fecha": ahora()})
        estado["siguiente_accion"] += 1
        guardar(estado)
        return codigo, {"mensaje": mensaje, "bloqueo": bloqueo, "simulacion": True}


if __name__ == "__main__":
    servidor = ThreadingHTTPServer(("127.0.0.1", PUERTO), Manejador)
    print(f"Bloqueador SIMULADO en http://127.0.0.1:{PUERTO} (clave de demo: SIMULADOR_API_KEY). Ctrl+C para parar.")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
