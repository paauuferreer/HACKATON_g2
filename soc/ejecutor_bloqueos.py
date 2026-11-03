"""
Ejecutor de bloqueos del Equipo 2.

La base de datos decide (reglas_bloqueo_auto, lista_blanca, decisiones_bloqueo_auto) y encola acciones
en acciones_bloqueo con estado PENDIENTE. Este proceso las ejecuta contra la API del reto, una por una,
y guarda la respuesta. No reintenta automáticamente: una acción con ERROR se revisa a mano.

Seguridad:
  - Por defecto NO llama a la API (modo simulación). Para ejecutar de verdad: BLOQUEO_AUTO_ACTIVO=1 en .env.
  - La clave de la API solo se lee de .env (API_TOKEN) y nunca se imprime.

Uso (desde la raíz del repo):
    .venv/bin/python soc/ejecutor_bloqueos.py            # bucle cada 60 s
    .venv/bin/python soc/ejecutor_bloqueos.py --una-vez  # un ciclo y termina

Variables en .env: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, API_BASE, API_TOKEN,
                   BLOQUEO_AUTO_ACTIVO (0/1), INTERVALO_SEGUNDOS (opcional).
"""
import os
import sys
import time
from pathlib import Path

import psycopg
import requests
from dotenv import load_dotenv
from psycopg.types.json import Jsonb

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

API_BASE = os.getenv("API_BASE", "https://hackathon-api-a6ckg4g2ejg4cda4.francecentral-01.azurewebsites.net").rstrip("/")
API_KEY = os.getenv("API_TOKEN") or os.getenv("BLOCK_API_KEY", "")
ACTIVO = os.getenv("BLOQUEO_AUTO_ACTIVO", "0") == "1"
INTERVALO = int(os.getenv("INTERVALO_SEGUNDOS", "60"))
LOTE = 20

SQL_SIGUIENTE = """
    SELECT accion_id, accion, usuario_objetivo, host(ip_objetivo) AS ip, motivo, origen
    FROM acciones_bloqueo
    WHERE estado = 'PENDIENTE' AND NOT simulacion
    ORDER BY fecha_solicitud
    LIMIT 1
    FOR UPDATE SKIP LOCKED
"""

SQL_RESULTADO = """
    UPDATE acciones_bloqueo
    SET estado = %s, http_status = %s, respuesta_api = %s, exito = %s, fecha_respuesta = now()
    WHERE accion_id = %s
"""


def llamar_api(accion: str, usuario: str | None, ip: str | None) -> tuple[int | None, dict, bool]:
    """Devuelve (http_status, respuesta, exito). Un solo objetivo por llamada, como exige la API."""
    ruta = "bloquear" if accion == "BLOQUEAR" else "liberar"
    cuerpo = {"ip": ip} if ip else {"usuario": usuario}
    try:
        r = requests.post(
            f"{API_BASE}/equipo-2/{ruta}",
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            json=cuerpo,
            timeout=15,
        )
    except requests.RequestException as e:
        return None, {"error": type(e).__name__, "detalle": str(e)[:500]}, False
    try:
        respuesta = r.json()
    except ValueError:
        respuesta = {"texto": r.text[:2000]}
    return r.status_code, respuesta, 200 <= r.status_code < 300


def ciclo(conn: psycopg.Connection) -> None:
    # Red de seguridad: alertas críticas que el trigger no llegó a evaluar
    creadas = conn.execute("SELECT evaluar_bloqueo_pendientes(24)").fetchone()[0]
    conn.commit()
    if creadas:
        print(f"[COLA]  {creadas} acción(es) nueva(s) encolada(s)")

    if not ACTIVO:
        pendientes = conn.execute(
            """SELECT accion, coalesce(host(ip_objetivo), usuario_objetivo), regla
               FROM acciones_bloqueo WHERE estado = 'PENDIENTE' AND NOT simulacion
               ORDER BY fecha_solicitud"""
        ).fetchall()
        conn.commit()
        for accion, objetivo, regla in pendientes:
            print(f"[SIMUL] {accion} {objetivo} ({regla or 'manual'}): no se llama a la API (BLOQUEO_AUTO_ACTIVO=0)")
        return

    if not API_KEY:
        print("[ERROR] Falta API_TOKEN en .env", file=sys.stderr)
        return

    for _ in range(LOTE):
        # Una transacción por acción: si el proceso cae, solo queda en duda una
        with conn.transaction():
            fila = conn.execute(SQL_SIGUIENTE).fetchone()
            if fila is None:
                return
            accion_id, accion, usuario, ip, _motivo, origen = fila
            status, respuesta, exito = llamar_api(accion, usuario, ip)
            estado = "EJECUTADA" if exito else "ERROR"
            conn.execute(SQL_RESULTADO, (estado, status, Jsonb(respuesta), exito, accion_id))
        print(f"[{estado}] {accion} {ip or usuario} ({origen}) -> HTTP {status}")


def main() -> None:
    una_vez = "--una-vez" in sys.argv
    modo = "REAL" if ACTIVO else "SIMULACIÓN"
    print(f"Ejecutor de bloqueos en modo {modo}; API {API_BASE}")
    with psycopg.connect(sslmode=os.getenv("PGSSLMODE", "require"), connect_timeout=15,
                         application_name="ejecutor-bloqueos") as conn:
        while True:
            try:
                ciclo(conn)
            except psycopg.Error as e:
                conn.rollback()
                print(f"[ERROR] Base de datos: {e.sqlstate or type(e).__name__}", file=sys.stderr)
            if una_vez:
                break
            time.sleep(INTERVALO)


if __name__ == "__main__":
    main()
