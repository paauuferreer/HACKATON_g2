"""
Genera docs/informe/datos.json para el informe final del Equipo 2 (solo lectura).

Fuentes:
  - PostgreSQL de Azure (vistas v_*; credenciales solo desde .env).
  - Analisis_economico_Sampol.xlsx (datos del director e hipótesis), leído como XML sin dependencias.

Uso (desde la raíz del repo):
    .venv/bin/python docs/informe/generar_datos.py [--excel RUTA]
"""
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import os

import psycopg
import requests
from dotenv import load_dotenv
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[2]
SALIDA = Path(__file__).resolve().parent / "datos.json"
EXCEL = ROOT.parent / "Analisis_economico_Sampol.xlsx"   # carpeta del proyecto, junto al repo
load_dotenv(ROOT / ".env")

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
PREFIJOS_TESTNET = ("192.0.2.", "198.51.100.", "203.0.113.")


def leer_excel(ruta: Path) -> dict:
    """Devuelve {hoja: {celda: valor}} con los valores calculados guardados en el libro."""
    z = zipfile.ZipFile(ruta)
    textos = []
    if "xl/sharedStrings.xml" in z.namelist():
        raiz = ET.fromstring(z.read("xl/sharedStrings.xml"))
        textos = ["".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])) for si in raiz.findall("m:si", NS)]
    libro = ET.fromstring(z.read("xl/workbook.xml"))
    hojas = [h.get("name") for h in libro.find("m:sheets", NS)]
    ficheros = sorted((n for n in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml", n)),
                      key=lambda n: int(re.findall(r"\d+", n)[0]))
    datos = {}
    for hoja, fichero in zip(hojas, ficheros):
        celdas = {}
        for c in ET.fromstring(z.read(fichero)).iter("{%s}c" % NS["m"]):
            v = c.find("m:v", NS)
            if v is None or v.text is None:
                continue
            valor = textos[int(v.text)] if c.get("t") == "s" else v.text
            try:
                valor = float(valor)
            except ValueError:
                pass
            celdas[c.get("r")] = valor
        datos[hoja] = celdas
    return datos


def reconstruir_ip(ip_raw: str | None) -> str | None:
    """'2030113150' -> '203.0.113.150' cuando coincide con un rango de documentación (TEST-NET)."""
    if not ip_raw or "." in ip_raw:
        return ip_raw
    for prefijo in PREFIJOS_TESTNET:
        compacto = prefijo.replace(".", "")
        if ip_raw.startswith(compacto) and 1 <= len(ip_raw) - len(compacto) <= 3:
            return prefijo + ip_raw[len(compacto):]
    return None


def estado_api() -> dict:
    """Código HTTP de GET /equipo-2/bloqueos con la clave de .env (nunca se guarda ni se imprime la clave)."""
    base, clave = os.getenv("API_BASE", "").rstrip("/"), os.getenv("API_TOKEN", "")
    if not base or not clave:
        return {"http": None, "detalle": "Sin API_BASE o API_TOKEN en .env"}
    try:
        r = requests.get(f"{base}/equipo-2/bloqueos", headers={"X-API-Key": clave}, timeout=15)
        return {"http": r.status_code, "detalle": "OK" if r.ok else r.text[:120]}
    except requests.RequestException as e:
        return {"http": None, "detalle": type(e).__name__}


def serializable(o):
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    raise TypeError(type(o))


CONSULTAS = {
    "kpis": "SELECT * FROM v_kpis",
    "por_gravedad": """SELECT soc_peligrosidad::text AS gravedad,
                              count(*) FILTER (WHERE NOT es_duplicada) AS unicas,
                              count(*) FILTER (WHERE es_duplicada) AS duplicadas
                       FROM alertas GROUP BY 1 ORDER BY 1""",
    "por_estado": "SELECT estado::text AS estado, count(*) AS total FROM alertas WHERE NOT es_duplicada GROUP BY 1",
    "por_clase": """SELECT coalesce(c.nombre, 'Sin clasificar') AS clase,
                           count(*) FILTER (WHERE NOT a.es_duplicada) AS unicas,
                           count(*) FILTER (WHERE a.es_duplicada OR a.soc_peligrosidad = 'INFORMATIVO'
                                            OR a.estado IN ('FALSA_ALARMA', 'NO_SOC')) AS ruido
                    FROM alertas a LEFT JOIN incibe_clases c ON c.clase_id = a.incibe_clase_id
                    GROUP BY 1 ORDER BY 2 DESC""",
    "por_sede": """SELECT coalesce(sede, 'Sin sede') AS sede, count(*) AS total,
                          count(*) FILTER (WHERE soc_peligrosidad = 'CRITICO') AS criticas
                   FROM alertas WHERE NOT es_duplicada GROUP BY 1 ORDER BY 2 DESC""",
    "por_franja": "SELECT franja, descripcion, total, reales, criticas, duplicadas FROM v_stats_franja ORDER BY orden",
    "por_hora": """SELECT to_char(periodo, 'YYYY-MM-DD HH24:00') AS hora, total, criticas
                   FROM v_stats_periodo WHERE granularidad = 'hora' ORDER BY periodo""",
    "avisos_por_hora": """SELECT to_char(date_trunc('hour', fecha_hora_correo AT TIME ZONE 'Europe/Madrid'), 'DD/MM HH24:00') AS hora,
                                 count(*) AS correos
                          FROM bandeja_entrada GROUP BY date_trunc('hour', fecha_hora_correo AT TIME ZONE 'Europe/Madrid')
                          ORDER BY date_trunc('hour', fecha_hora_correo AT TIME ZONE 'Europe/Madrid')""",
    "cadena_victimas": """SELECT orden_victima, victima, equipos, sedes, ips, num_fases, fase_maxima,
                                 to_char(inicio_aviso_local, 'DD/MM HH24:MI') AS primer_aviso,
                                 to_char(inicio_evento_local, 'DD/MM HH24:MI') AS primer_evento,
                                 min_aviso_desde_victima_anterior AS min_desde_anterior,
                                 to_char(aviso_compromiso_local, 'HH24:MI') AS aviso_compromiso,
                                 to_char(aviso_primera_critica_local, 'HH24:MI') AS aviso_primera_critica,
                                 min_ganados_detectando_compromiso AS min_ganados,
                                 estado_bloqueo, origen_bloqueo, bloqueo_confirmado
                          FROM v_cadena_victimas ORDER BY orden_victima""",
    "cadena_fases": """SELECT victima, equipo, sede, ip, fase, nombre_fase, orden_fase,
                              split_part(titulo, ' · ', 1) AS titulo, soc_peligrosidad::text AS gravedad, id_alerta_soc,
                              to_char(aviso_local, 'DD/MM HH24:MI') AS aviso, to_char(evento_local, 'DD/MM HH24:MI') AS evento,
                              min_desde_fase_anterior, min_desde_inicio_victima
                       FROM v_cadena_ransomware ORDER BY orden_victima, evento_local, orden_fase""",
    "cadena_ip_raw": """SELECT DISTINCT lower(btrim(usuario_implicado)) AS victima, ip_raw
                        FROM alertas WHERE usuario_implicado ILIKE '%moreno@%' AND ip_raw IS NOT NULL""",
    "prediccion": "SELECT * FROM v_cadena_prediccion",
    "fases": "SELECT fase, count(*) AS total FROM v_fases_alertas GROUP BY 1",
    "decisiones": """SELECT regla_id, decision, tipo_objetivo, count(*) AS total
                     FROM decisiones_bloqueo_auto GROUP BY 1, 2, 3 ORDER BY 1, 2, 3""",
    "acciones": """SELECT usuario_objetivo, host(ip_objetivo) AS ip, origen, regla, estado,
                          to_char(fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI') AS solicitada
                   FROM acciones_bloqueo ORDER BY fecha_solicitud""",
    "outlook": "SELECT ruta, correos FROM v_outlook_resumen ORDER BY orden",
    "autenticidad": "SELECT remitente_correo, verificada, motivo, correos FROM v_autenticidad_resumen ORDER BY correos DESC",
    "otros_casos": """SELECT id_alerta_soc, lower(usuario_implicado) AS usuario, equipo_afectado AS equipo, sede,
                             soc_peligrosidad::text AS gravedad, split_part(titulo, ' · ', 1) AS titulo,
                             to_char(fecha_hora_correo AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI') AS aviso
                      FROM alertas
                      WHERE NOT es_duplicada AND plegar(titulo) ~ %s
                      ORDER BY fecha_hora_correo""",
    "compromisos_aislados": """SELECT d.valor_objetivo AS usuario, d.decision, left(d.motivo, 120) AS motivo
                               FROM decisiones_bloqueo_auto d WHERE d.regla_id = 'AUTO-06' AND d.decision = 'DESCARTAR'
                               ORDER BY 1""",
    "malformados": "SELECT count(*) AS total, count(*) FILTER (WHERE es_sospechoso) AS sospechosos FROM correos_malformados",
    "ingesta": """SELECT max(fecha_recepcion_bd) AT TIME ZONE 'Europe/Madrid' AS ultima_insercion,
                         max(fecha_hora_correo) AT TIME ZONE 'Europe/Madrid' AS ultimo_correo,
                         round(extract(epoch FROM now() - max(fecha_recepcion_bd)) / 60) AS min_sin_ingesta
                  FROM bandeja_entrada""",
    "demo": "SELECT accion, estado, count(*) AS total FROM acciones_bloqueo WHERE simulacion GROUP BY 1, 2",
    "migraciones": "SELECT version, to_char(applied_at AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI') AS aplicada FROM schema_migrations ORDER BY version",
}
PATRON_OTROS = ("persistencia dirigida|cambio de cuenta de pago|llamada intenta|cuenta administrativa|"
                "datos perdidos|equipo sustraido|captura de trafico")


def main() -> None:
    excel = Path(sys.argv[sys.argv.index("--excel") + 1]) if "--excel" in sys.argv else EXCEL
    datos = {"generado": datetime.now().strftime("%d/%m/%Y %H:%M")}
    with psycopg.connect(sslmode="require", connect_timeout=15, row_factory=dict_row,
                         options="-c statement_timeout=60000") as conn:
        conn.read_only = True
        for nombre, sql in CONSULTAS.items():
            params = (PATRON_OTROS,) if nombre == "otros_casos" else None
            datos[nombre] = conn.execute(sql, params).fetchall()
    datos["kpis"] = datos["kpis"][0]
    datos["ingesta"] = datos["ingesta"][0]
    datos["api"] = estado_api()
    datos["prediccion"] = datos["prediccion"][0] if datos["prediccion"] else {}

    # IPs reconstruidas (sin puntos en el correo original)
    reconstruidas = {}
    for fila in datos.pop("cadena_ip_raw"):
        ip = reconstruir_ip(fila["ip_raw"])
        if ip:
            reconstruidas.setdefault(fila["victima"], set()).add(ip)
    datos["ips_reconstruidas"] = {k: sorted(v) for k, v in reconstruidas.items()}

    # Ruido real: duplicadas + informativas + falsas alarmas + no SOC + malformados, sobre correos recibidos
    k = datos["kpis"]
    informativas = next((g["unicas"] for g in datos["por_gravedad"] if g["gravedad"] == "INFORMATIVO"), 0)
    ruido = k["duplicadas"] + informativas + k["falsas_alarmas"] + k["no_soc"] + k["malformados"]
    datos["ruido_real"] = {"ruido": ruido, "correos": k["correos_recibidos"],
                           "pct": round(ruido / k["correos_recibidos"], 4) if k["correos_recibidos"] else 0,
                           "componentes": {"duplicadas": k["duplicadas"], "informativas": informativas,
                                           "falsas_alarmas": k["falsas_alarmas"], "no_soc": k["no_soc"],
                                           "malformados": k["malformados"]}}

    if excel.exists():
        libro = leer_excel(excel)
        datos["excel"] = {"fichero": excel.name, "hipotesis": libro.get("Hipótesis", {}),
                          "calculos": libro.get("Cálculos", {}), "comparativa": libro.get("Comparativa", {}),
                          "mejoras": libro.get("Mejoras", {}), "resumen": libro.get("Resumen", {}),
                          "automatizacion": libro.get("Automatización", {}), "datosbd": libro.get("DatosBD", {})}
    SALIDA.write_text(json.dumps(datos, ensure_ascii=False, indent=1, default=serializable), encoding="utf-8")
    print(f"datos.json: {len(datos['cadena_victimas'])} víctimas, {k['correos_recibidos']} correos, "
          f"ruido real {datos['ruido_real']['pct']:.1%}")


if __name__ == "__main__":
    main()
