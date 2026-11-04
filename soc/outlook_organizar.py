"""
Organiza el buzón de Outlook del equipo según lo que decide la base de datos (migración 011, decisión D-008).

La base de datos decide la carpeta y las etiquetas de cada correo (vista v_outlook_pendientes).
Este script solo las aplica con Microsoft Graph y registra el resultado en outlook_sincronizacion.
  * Nunca lee ni interpreta el contenido de los correos: solo usa identificadores y decisiones de la BD.
  * Solo toca correos que ya están guardados en bandeja_entrada, así que el flujo de Power Automate
    (que se dispara en la Bandeja de entrada) nunca pierde un correo.
  * Conserva las categorías que haya puesto una persona a mano; solo gestiona las de outlook_categorias.

Modos:
  (por defecto) SIMULACIÓN: inicia sesión, comprueba que encuentra los correos y muestra lo que haría.
                No crea carpetas ni modifica correos ni la BD.
  OUTLOOK_APLICAR=1 en .env: aplica de verdad.
  --sin-graph:  solo muestra el plan desde la BD, sin iniciar sesión.
  --una-vez:    un ciclo y termina (si no, repite cada OUTLOOK_INTERVALO_SEGUNDOS).

Uso (desde la raíz del repo):
    .venv/bin/pip install msal requests psycopg[binary] python-dotenv
    .venv/bin/python soc/outlook_organizar.py --sin-graph --una-vez     # plan, sin Outlook
    .venv/bin/python soc/outlook_organizar.py --una-vez                 # simulación con Outlook
    OUTLOOK_APLICAR=1 .venv/bin/python soc/outlook_organizar.py         # aplicar cada 2 min

Variables en .env: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, MS_CLIENT_ID, MS_TENANT_ID,
                   OUTLOOK_MAILBOX (opcional: buzón distinto del de la sesión), OUTLOOK_APLICAR (0/1),
                   OUTLOOK_INTERVALO_SEGUNDOS (opcional, 120 por defecto).
Inicio de sesión: flujo device code (abre la URL que se muestra e introduce el código con la cuenta del buzón).
El token se guarda en data/msal_cache_outlook.json (data/ está en .gitignore). No se imprime ningún token.
"""
import os
import sys
import time
from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

GRAPH = "https://graph.microsoft.com/v1.0"
CLIENT_ID = os.getenv("MS_CLIENT_ID", "")
TENANT = os.getenv("MS_TENANT_ID") or "organizations"
BUZON = os.getenv("OUTLOOK_MAILBOX", "").strip()
APLICAR = os.getenv("OUTLOOK_APLICAR", "0") == "1"
INTERVALO = int(os.getenv("OUTLOOK_INTERVALO_SEGUNDOS", "120"))
CACHE = ROOT / "data" / "msal_cache_outlook.json"
SCOPES_COMPLETOS = ["Mail.ReadWrite", "MailboxSettings.ReadWrite"]  # MailboxSettings: colores de las etiquetas
SCOPES_MINIMOS = ["Mail.ReadWrite"]
LOTE = 50
MUESTRA_SIMULACION = 10


class PermisoError(Exception):
    """El token no permite escribir en el buzón."""


# ----------------------------------------------------------------------------
# Autenticación (delegada, device code) con caché local
# ----------------------------------------------------------------------------
class Sesion:
    def __init__(self):
        import msal

        if not CLIENT_ID:
            raise SystemExit("Falta MS_CLIENT_ID en .env")
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        self.cache = msal.SerializableTokenCache()
        if CACHE.exists():
            self.cache.deserialize(CACHE.read_text(encoding="utf-8"))
        self.app = msal.PublicClientApplication(
            CLIENT_ID, authority=f"https://login.microsoftonline.com/{TENANT}", token_cache=self.cache)
        self.scopes = None

    def _guardar(self):
        if self.cache.has_state_changed:
            CACHE.write_text(self.cache.serialize(), encoding="utf-8")
            try:
                CACHE.chmod(0o600)
            except OSError:
                pass

    def token(self) -> str:
        cuentas = self.app.get_accounts()
        for scopes in ([self.scopes] if self.scopes else [SCOPES_COMPLETOS, SCOPES_MINIMOS]):
            if cuentas:
                r = self.app.acquire_token_silent(scopes, account=cuentas[0])
                if r and "access_token" in r:
                    self.scopes = scopes
                    self._guardar()
                    return r["access_token"]
        # Sin token válido: inicio de sesión interactivo. Primero con colores; si no hay consentimiento, sin ellos.
        for scopes in (SCOPES_COMPLETOS, SCOPES_MINIMOS):
            flujo = self.app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flujo:
                print(f"[AVISO] No se pudo iniciar sesión con {scopes}: {flujo.get('error_description', flujo.get('error'))}")
                continue
            print(flujo["message"], flush=True)
            r = self.app.acquire_token_by_device_flow(flujo)
            if "access_token" in r:
                self.scopes = scopes
                self._guardar()
                if scopes is SCOPES_MINIMOS:
                    print("[AVISO] Sin MailboxSettings.ReadWrite: las etiquetas se aplican, pero sin colores.")
                return r["access_token"]
            print(f"[AVISO] Inicio de sesión rechazado con {scopes}: {r.get('error_description', r.get('error'))}")
        raise SystemExit("No se pudo obtener un token con Mail.ReadWrite. Revisa los permisos de la aplicación (Client ID).")


# ----------------------------------------------------------------------------
# Cliente de Microsoft Graph
# ----------------------------------------------------------------------------
class Graph:
    def __init__(self, sesion: Sesion, buzon: str = ""):
        self.sesion = sesion
        self.base = f"/users/{buzon}" if buzon else "/me"
        self.http = requests.Session()

    def pedir(self, metodo: str, ruta: str, **kw) -> requests.Response:
        for intento in range(5):
            cabeceras = {"Authorization": f"Bearer {self.sesion.token()}", "Content-Type": "application/json"}
            r = self.http.request(metodo, GRAPH + self.base + ruta, headers=cabeceras, timeout=30, **kw)
            if r.status_code in (429, 503, 504):
                espera = int(r.headers.get("Retry-After", 2 ** intento))
                time.sleep(min(espera, 60))
                continue
            return r
        return r

    @staticmethod
    def _error(r: requests.Response) -> str:
        try:
            e = r.json().get("error", {})
            return f"HTTP {r.status_code} {e.get('code', '')}: {e.get('message', '')[:200]}"
        except ValueError:
            return f"HTTP {r.status_code}"

    def json(self, metodo: str, ruta: str, **kw) -> dict:
        r = self.pedir(metodo, ruta, **kw)
        if r.status_code == 403:
            raise PermisoError(self._error(r))
        if not r.ok:
            raise RuntimeError(self._error(r))
        return r.json() if r.content else {}


def comillas(texto: str) -> str:
    """Escapa un literal para $filter de OData."""
    return texto.replace("'", "''")


# ----------------------------------------------------------------------------
# Carpetas y etiquetas
# ----------------------------------------------------------------------------
def asegurar_carpetas(g: Graph, carpetas: list[tuple[str, str]], crear: bool) -> dict[str, str | None]:
    """Devuelve {codigo: id de carpeta}. Crea las que falten si crear=True (si no, None)."""
    padre_raiz = g.json("GET", "/mailFolders/inbox", params={"$select": "id"})["id"]
    conocidas: dict[tuple[str, str], str] = {}
    ids: dict[str, str | None] = {}
    for codigo, ruta in carpetas:
        padre = padre_raiz
        partes = ruta.split("/")
        for i, nombre in enumerate(partes):
            clave = (padre, nombre)
            if clave not in conocidas:
                hijos = g.json("GET", f"/mailFolders/{padre}/childFolders",
                               params={"$filter": f"displayName eq '{comillas(nombre)}'", "$select": "id,displayName"})
                if hijos.get("value"):
                    conocidas[clave] = hijos["value"][0]["id"]
                elif crear:
                    nueva = g.json("POST", f"/mailFolders/{padre}/childFolders", json={"displayName": nombre})
                    conocidas[clave] = nueva["id"]
                    print(f"[CARPETA] creada «Bandeja de entrada/{'/'.join(partes[:i + 1])}»")
                else:
                    padre = None
                    break
            padre = conocidas[clave]
        ids[codigo] = padre
    return ids


def asegurar_categorias(g: Graph, categorias: list[tuple[str, str]], crear: bool) -> None:
    """Crea en la lista maestra las etiquetas que falten, con su color. Si no hay permiso, avisa y sigue."""
    try:
        existentes = {c["displayName"] for c in g.json("GET", "/outlook/masterCategories").get("value", [])}
    except PermisoError:
        print("[AVISO] Sin permiso para la lista maestra de categorías: las etiquetas irán sin color.")
        return
    faltan = [(n, c) for n, c in categorias if n not in existentes]
    if not crear:
        if faltan:
            print(f"[SIMUL] se crearían {len(faltan)} etiquetas con color: {', '.join(n for n, _ in faltan[:6])}…")
        return
    for nombre, color in faltan:
        try:
            g.json("POST", "/outlook/masterCategories", json={"displayName": nombre, "color": color})
        except PermisoError:
            print("[AVISO] Sin permiso para crear categorías con color: se aplican igualmente, sin color.")
            return
    if faltan:
        print(f"[ETIQUETAS] creadas {len(faltan)} etiquetas con color")


def carpetas_excluidas(g: Graph) -> set[str]:
    """Enviados, borrados y borradores: ahí no se busca el original."""
    ids = set()
    for nombre in ("sentitems", "deleteditems", "drafts"):
        try:
            ids.add(g.json("GET", f"/mailFolders/{nombre}", params={"$select": "id"})["id"])
        except (RuntimeError, PermisoError):
            pass
    return ids


# ----------------------------------------------------------------------------
# Un correo
# ----------------------------------------------------------------------------
def localizar(g: Graph, id_outlook: str, excluidas: set[str]) -> dict | None:
    """Busca el correo en el buzón por InternetMessageId (o por id de Graph si es lo que guardó la ingesta)."""
    if not id_outlook or id_outlook.startswith("sites:"):
        return None
    campos = "id,categories,parentFolderId"
    if id_outlook.startswith("<"):
        r = g.json("GET", "/messages", params={"$filter": f"internetMessageId eq '{comillas(id_outlook)}'",
                                                "$select": campos, "$top": "10"})
        candidatos = [m for m in r.get("value", []) if m.get("parentFolderId") not in excluidas]
        return candidatos[0] if candidatos else None
    resp = g.pedir("GET", f"/messages/{id_outlook}", params={"$select": campos})
    if resp.status_code == 404:
        return None
    if resp.status_code == 403:
        raise PermisoError(Graph._error(resp))
    if not resp.ok:
        raise RuntimeError(Graph._error(resp))
    return resp.json()


def categorias_finales(actuales: list[str], deseadas: list[str], gestionadas: set[str]) -> list[str]:
    """Respeta las etiquetas puestas a mano (no gestionadas) y fija exactamente las gestionadas."""
    manuales = [c for c in actuales if c not in gestionadas]
    return manuales + [c for c in deseadas if c not in manuales]


def aplicar_correo(g: Graph, mensaje: dict, destino_id: str, deseadas: list[str], gestionadas: set[str]) -> tuple[str, list[str]]:
    """Ajusta etiquetas y mueve. Devuelve (id de Graph tras moverlo, lista de cambios hechos)."""
    cambios = []
    finales = categorias_finales(mensaje.get("categories") or [], deseadas, gestionadas)
    if set(finales) != set(mensaje.get("categories") or []):
        g.json("PATCH", f"/messages/{mensaje['id']}", json={"categories": finales})
        cambios.append("etiquetas")
    nuevo_id = mensaje["id"]
    if destino_id and mensaje.get("parentFolderId") != destino_id:
        nuevo_id = g.json("POST", f"/messages/{mensaje['id']}/move", json={"destinationId": destino_id})["id"]
        cambios.append("carpeta")
    return nuevo_id, cambios


# ----------------------------------------------------------------------------
# Ciclo
# ----------------------------------------------------------------------------
SQL_PENDIENTES = """
    SELECT correo_id, id_outlook, carpeta_codigo, carpeta_ruta, categorias, huella, coalesce(referencia, '') AS referencia
    FROM v_outlook_pendientes
    LIMIT %s
"""


def plan(filas) -> None:
    resumen = Counter(f[3] for f in filas)
    for ruta, n in sorted(resumen.items()):
        print(f"[PLAN]  {n:4d} → Bandeja de entrada/{ruta}")


def ciclo(conn, g: Graph | None) -> None:
    activo = conn.execute("SELECT organizacion_activa FROM config_outlook WHERE id = 1").fetchone()
    if not activo or not activo[0]:
        print("[PAUSA] organizacion_activa = FALSE en config_outlook")
        conn.commit()
        return
    carpetas = conn.execute("SELECT codigo, ruta FROM outlook_carpetas ORDER BY orden").fetchall()
    categorias = conn.execute("SELECT nombre, color FROM outlook_categorias ORDER BY orden").fetchall()
    filas = conn.execute(SQL_PENDIENTES, (LOTE,)).fetchall()
    conn.commit()
    gestionadas = {n for n, _ in categorias}
    print(f"[COLA]  {len(filas)} correo(s) por ordenar (máx. {LOTE} por ciclo)")
    plan(filas)
    if g is None or not filas:
        return

    ids = asegurar_carpetas(g, carpetas, crear=APLICAR)
    asegurar_categorias(g, categorias, crear=APLICAR)
    excluidas = carpetas_excluidas(g)
    hechos = Counter()

    for correo_id, id_outlook, codigo, ruta, deseadas, huella, referencia in (filas if APLICAR else filas[:MUESTRA_SIMULACION]):
        etiqueta = referencia or str(correo_id)[:8]
        try:
            mensaje = localizar(g, id_outlook, excluidas)
            if mensaje is None:
                hechos["no encontrados"] += 1
                if APLICAR:
                    conn.execute("SELECT registrar_sincronizacion_outlook(%s,%s,%s,%s,%s,%s,%s)",
                                 (correo_id, huella, codigo, deseadas, None, "NO_ENCONTRADO", "No está en el buzón"))
                    conn.commit()
                print(f"[NO ENCONTRADO] {etiqueta}")
                continue
            if not APLICAR:
                hechos["encontrados"] += 1
                print(f"[SIMUL] {etiqueta}: iría a «{ruta}» con {len(deseadas)} etiqueta(s)")
                continue
            nuevo_id, cambios = aplicar_correo(g, mensaje, ids.get(codigo), list(deseadas), gestionadas)
            conn.execute("SELECT registrar_sincronizacion_outlook(%s,%s,%s,%s,%s,%s,%s)",
                         (correo_id, huella, codigo, deseadas, nuevo_id, "APLICADO", ", ".join(cambios) or "sin cambios"))
            conn.commit()
            hechos["aplicados"] += 1
            print(f"[OK]    {etiqueta} → {ruta} ({', '.join(cambios) or 'ya estaba bien'})")
        except PermisoError as e:
            conn.rollback()
            raise SystemExit(f"[PERMISO] {e}. Hace falta Mail.ReadWrite delegado para el buzón: "
                             "borra data/msal_cache_outlook.json y vuelve a iniciar sesión, o usa el plan B (Power Automate).")
        except Exception as e:  # un correo con problemas no detiene el resto
            conn.rollback()
            hechos["errores"] += 1
            if APLICAR:
                conn.execute("SELECT registrar_sincronizacion_outlook(%s,%s,%s,%s,%s,%s,%s)",
                             (correo_id, huella, codigo, deseadas, None, "ERROR", str(e)))
                conn.commit()
            print(f"[ERROR] {etiqueta}: {e}", file=sys.stderr)
    print("[RESUMEN] " + ", ".join(f"{k}: {v}" for k, v in hechos.items()))


def main() -> None:
    import psycopg

    una_vez = "--una-vez" in sys.argv
    sin_graph = "--sin-graph" in sys.argv
    modo = "SOLO PLAN (sin Outlook)" if sin_graph else ("APLICAR" if APLICAR else "SIMULACIÓN")
    print(f"Organizador de Outlook en modo {modo}; buzón: {BUZON or 'el de la sesión'}")
    g = None if sin_graph else Graph(Sesion(), BUZON)
    with psycopg.connect(sslmode=os.getenv("PGSSLMODE", "require"), connect_timeout=15,
                         application_name="outlook-organizar") as conn:
        while True:
            try:
                ciclo(conn, g)
            except psycopg.Error as e:
                conn.rollback()
                print(f"[ERROR] Base de datos: {e.sqlstate or type(e).__name__}", file=sys.stderr)
            except (RuntimeError, requests.RequestException) as e:
                print(f"[ERROR] Graph: {e}", file=sys.stderr)
            if una_vez:
                break
            time.sleep(INTERVALO)


if __name__ == "__main__":
    main()
