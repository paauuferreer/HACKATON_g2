"""
Demostración de la contención contra el Bloqueador SIMULADO (demo/bloqueador_simulado.py).

Refleja la cola REAL (acciones_bloqueo PENDIENTE, simulacion = FALSE) sin modificarla: por cada objetivo crea una fila
espejo con simulacion = TRUE, la ejecuta contra el simulador, la verifica con GET y guarda la respuesta. Las vistas y los
ejecutores reales ignoran las filas con simulacion = TRUE, así que el estado real no cambia.

Salvaguarda: solo habla con 127.0.0.1/localhost y nunca usa la clave real (API_TOKEN).

Uso (desde la raíz del repo):
    .venv/bin/python demo/demo_bloqueos.py --una-vez
    .venv/bin/python demo/demo_bloqueos.py                       # bucle cada 60 s
    .venv/bin/python demo/demo_bloqueos.py --liberar fmoreno@sampol.com --responsable "Equipo 2" --motivo "..."
    .venv/bin/python demo/demo_bloqueos.py --reset               # borra solo lo creado por la demo
"""
import argparse
import ipaddress
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import psycopg
import requests
from dotenv import load_dotenv
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
URL = os.getenv("SIMULADOR_URL", "http://127.0.0.1:8090").rstrip("/")
CLAVE = os.getenv("SIMULADOR_API_KEY", "demo-local")
DEMO = "DEMO"

SQL_COLA = """
    SELECT b.accion_id, b.accion, b.usuario_objetivo, host(b.ip_objetivo) AS ip, b.motivo, b.regla, b.alerta_id, b.origen
    FROM acciones_bloqueo b
    WHERE b.estado = 'PENDIENTE' AND NOT b.simulacion
      AND NOT EXISTS (SELECT 1 FROM acciones_bloqueo s
                      WHERE s.simulacion AND s.solicitado_por = %(demo)s AND s.accion = b.accion
                        AND s.estado = 'EJECUTADA'
                        AND coalesce(lower(s.usuario_objetivo), host(s.ip_objetivo)) = coalesce(lower(b.usuario_objetivo), host(b.ip_objetivo)))
    ORDER BY b.fecha_solicitud
"""
SQL_ESPEJO = """
    INSERT INTO acciones_bloqueo (accion, usuario_objetivo, ip_objetivo, motivo, regla, alerta_id, solicitado_por,
                                  simulacion, estado, origen, fecha_envio)
    VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, 'EN_CURSO', %s, now())
    RETURNING accion_id
"""
SQL_CIERRE = """
    UPDATE acciones_bloqueo
    SET estado = %s, exito = %s, http_status = %s, respuesta_api = %s, fecha_respuesta = now()
    WHERE accion_id = %s AND simulacion
"""


def salvaguarda() -> None:
    host = urlparse(URL).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit(f"[ABORTADO] SIMULADOR_URL apunta a {host!r}: la demo solo habla con el simulador local.")
    real = os.getenv("API_TOKEN") or ""
    if real and CLAVE == real:
        sys.exit("[ABORTADO] SIMULADOR_API_KEY no puede ser la clave real.")


def llamar(metodo: str, ruta: str, **kw) -> requests.Response:
    return requests.request(metodo, f"{URL}{ruta}", headers={"X-API-Key": CLAVE}, timeout=10, **kw)


def objetivo_body(usuario, ip) -> dict:
    return {"ip": ip} if ip else {"usuario": usuario}


def verificar(usuario, ip) -> dict | None:
    tipo, valor = ("ip", ip) if ip else ("usuario", usuario)
    r = llamar("GET", "/equipo-2/bloqueos", params={"tipo": tipo, "limit": 100})
    if r.status_code != 200:
        return None
    return next((b for b in r.json() if b["valor"].lower() == valor.lower()), None)


def ciclo(conn: psycopg.Connection) -> None:
    cola = conn.execute(SQL_COLA, {"demo": DEMO}).fetchall()
    if not cola:
        print("[DEMO] Nada nuevo en la cola real.")
    for accion_id, accion, usuario, ip, motivo, regla, alerta_id, origen in cola:
        with conn.transaction():
            espejo = conn.execute(SQL_ESPEJO, (accion, usuario, ip, f"SIMULACIÓN: {motivo}", regla, alerta_id,
                                               DEMO, origen)).fetchone()[0]
        ruta = "/equipo-2/bloquear" if accion == "BLOQUEAR" else "/equipo-2/liberar"
        try:
            r = llamar("POST", ruta, json=objetivo_body(usuario, ip))
            datos = r.json()
        except (requests.RequestException, ValueError) as e:
            r, datos = None, {"error": type(e).__name__}
        comprobado = verificar(usuario, ip) if r is not None and r.status_code in (200, 201) else None
        ok = bool(comprobado) and comprobado["activo"] == (accion == "BLOQUEAR")
        respuesta = {"simulacion": True, "origen_real": str(accion_id), "respuesta": datos,
                     "verificacion_get": comprobado}
        with conn.transaction():
            conn.execute(SQL_CIERRE, ("EJECUTADA" if ok else "ERROR", ok, r.status_code if r is not None else None,
                                      Jsonb(respuesta), espejo))
        print(f"[DEMO] {accion} {usuario or ip} ({regla or origen}) -> HTTP {r.status_code if r is not None else '—'} · "
              f"{'verificado' if ok else 'ERROR'}")


def liberar(conn: psycopg.Connection, valor: str, responsable: str, motivo: str) -> None:
    try:
        usuario, ip = None, str(ipaddress.ip_address(valor))
    except ValueError:
        usuario, ip = valor, None
    with conn.transaction():
        espejo = conn.execute(SQL_ESPEJO, ("LIBERAR", usuario, ip, f"SIMULACIÓN: {motivo}", "MANUAL", None,
                                           f"{DEMO}:{responsable}"[:100], "MANUAL")).fetchone()[0]
    r = llamar("POST", "/equipo-2/liberar", json=objetivo_body(usuario, ip))
    comprobado = verificar(usuario, ip)
    ok = r.status_code == 200 and comprobado is not None and not comprobado["activo"]
    with conn.transaction():
        conn.execute(SQL_CIERRE, ("EJECUTADA" if ok else "ERROR", ok, r.status_code,
                                  Jsonb({"simulacion": True, "respuesta": r.json(), "verificacion_get": comprobado}), espejo))
    print(f"[DEMO] LIBERAR {valor} por {responsable} -> HTTP {r.status_code} · {'verificado' if ok else 'ERROR'}")


def reset(conn: psycopg.Connection) -> None:
    with conn.transaction():
        n = conn.execute("DELETE FROM acciones_bloqueo WHERE simulacion AND solicitado_por LIKE %s",
                         (DEMO + "%",)).rowcount
    estado = ROOT / "data" / "simulador_bloqueos.json"
    if estado.exists():
        estado.unlink()
    print(f"[DEMO] Borradas {n} filas de simulación y el estado del simulador (reinicia el simulador).")


def main() -> None:
    p = argparse.ArgumentParser(description="Demostración de bloqueos contra el simulador local")
    p.add_argument("--una-vez", action="store_true")
    p.add_argument("--liberar", metavar="USUARIO_O_IP")
    p.add_argument("--responsable", default="Equipo 2")
    p.add_argument("--motivo", default="Liberación de demostración")
    p.add_argument("--reset", action="store_true")
    a = p.parse_args()
    salvaguarda()
    with psycopg.connect(sslmode=os.getenv("PGSSLMODE", "require"), connect_timeout=15,
                         application_name="demo-bloqueos") as conn:
        if a.reset:
            return reset(conn)
        if a.liberar:
            return liberar(conn, a.liberar, a.responsable, a.motivo)
        while True:
            ciclo(conn)
            if a.una_vez:
                break
            time.sleep(60)


if __name__ == "__main__":
    main()
