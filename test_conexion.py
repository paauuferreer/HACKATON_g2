"""
Prueba de conexión del Equipo 2: PostgreSQL de Azure + API de bloqueo (solo lectura).
Uso:
    python -m venv .venv && source .venv/bin/activate
    pip install "psycopg[binary]" python-dotenv requests
    python test_conexion.py
No llama a /bloquear ni a /liberar: solo consulta /equipo-2/bloqueos.
"""
import os
import json
import sys

import psycopg
import requests
from dotenv import load_dotenv

load_dotenv()


def ok(msg):
    print(f"[OK]    {msg}")


def fail(msg):
    print(f"[FALLO] {msg}")


# ---------------------------------------------------------------- BBDD
def test_db():
    print("\n=== PostgreSQL (Azure) ===")
    try:
        with psycopg.connect(sslmode="require", connect_timeout=15) as conn:
            version, user, db = conn.execute(
                "SELECT version(), current_user, current_database()"
            ).fetchone()
            ok(f"Conectado como '{user}' a '{db}'")
            print(f"        {version.split(',')[0]}")

            tablas = conn.execute(
                """SELECT table_schema || '.' || table_name
                   FROM information_schema.tables
                   WHERE table_schema NOT IN ('pg_catalog','information_schema')
                   ORDER BY 1"""
            ).fetchall()
            ok(f"Tablas existentes: {len(tablas)} {[t[0] for t in tablas][:10]}")

            # ¿Podemos crear objetos? (necesario para el esquema)
            conn.execute("CREATE TABLE IF NOT EXISTS _test_permisos (id int)")
            conn.execute("DROP TABLE _test_permisos")
            conn.rollback()  # no dejamos rastro
            ok("Permisos para CREATE TABLE en public")

            exts = conn.execute(
                "SELECT name FROM pg_available_extensions WHERE name IN ('pgcrypto','pg_trgm','uuid-ossp') ORDER BY 1"
            ).fetchall()
            ok(f"Extensiones disponibles útiles: {[e[0] for e in exts]}")

            tz = conn.execute("SHOW timezone").fetchone()[0]
            ok(f"Zona horaria del servidor: {tz}")
        return True
    except Exception as e:
        fail(f"{type(e).__name__}: {e}")
        return False


# ---------------------------------------------------------------- API
def test_api():
    print("\n=== API de bloqueo ===")
    base = os.environ.get("API_BASE", "").rstrip("/")
    token = os.environ.get("API_TOKEN", "")
    if not base or not token:
        fail("Faltan API_BASE o API_TOKEN en .env")
        return False

    # 1) Leer el contrato OpenAPI para saber cómo se envía el token
    try:
        spec = requests.get(f"{base}/openapi.json", timeout=20).json()
    except Exception as e:
        fail(f"No se pudo leer /openapi.json: {e}")
        return False

    esquemas = spec.get("components", {}).get("securitySchemes", {})
    print("        securitySchemes:", json.dumps(esquemas, ensure_ascii=False))
    print("        Endpoints del equipo 2:")
    for path, metodos in spec.get("paths", {}).items():
        if "equipo-2" in path:
            for m, d in metodos.items():
                body = d.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
                print(f"          {m.upper():6} {path}  body={json.dumps(body, ensure_ascii=False)}")

    # 2) Construir la cabecera según lo que diga el spec
    headers, params = {}, {}
    for s in esquemas.values():
        if s.get("type") == "http" and s.get("scheme", "").lower() == "bearer":
            headers["Authorization"] = f"Bearer {token}"
        elif s.get("type") == "apiKey":
            if s.get("in") == "header":
                headers[s["name"]] = token
            elif s.get("in") == "query":
                params[s["name"]] = token
    if not headers and not params:
        headers["Authorization"] = f"Bearer {token}"  # suposición por defecto
        print("        (sin securitySchemes: pruebo con Bearer)")

    # 3) Solo lectura: listado de bloqueos
    r = requests.get(f"{base}/equipo-2/bloqueos", headers=headers, params=params, timeout=20)
    if r.ok:
        ok(f"GET /equipo-2/bloqueos -> {r.status_code}")
        print("        ", r.text[:500])
        print("        Cabecera de auth que funciona:", list(headers.keys()) or list(params.keys()))
        return True
    fail(f"GET /equipo-2/bloqueos -> {r.status_code} {r.text[:300]}")
    return False


if __name__ == "__main__":
    db = test_db()
    api = test_api()
    print("\nRESUMEN:", "BBDD OK" if db else "BBDD FALLA", "|", "API OK" if api else "API FALLA")
    sys.exit(0 if db and api else 1)
