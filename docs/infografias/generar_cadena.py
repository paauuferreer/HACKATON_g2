"""
Regenera la infografía «Cadena Moreno» (docs/infografias/cadena_moreno.html) con los datos actuales de la BD.

Solo lectura: consulta v_fases_alertas, v_bloqueos_activos, decisiones_bloqueo_auto, v_cadena_prediccion y
acciones_bloqueo, e inyecta el JSON en plantilla_cadena.html.

Uso (desde la raíz del repo):
    .venv/bin/python docs/infografias/generar_cadena.py
"""
import json
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

DIR = Path(__file__).resolve().parent
load_dotenv(DIR.parent.parent / ".env")

SQL = r"""
SELECT json_build_object(
 'generado', to_char(now() AT TIME ZONE 'Europe/Madrid', 'DD/MM/YYYY HH24:MI'),
 'fases', (SELECT json_agg(json_build_object('fase', fase, 'orden', orden, 'nombre', nombre) ORDER BY orden) FROM fases_ataque),
 'victimas', (SELECT json_agg(v ORDER BY v.inicio) FROM (
    SELECT fa.victima, min(fa.equipo) AS equipo, min(fa.sede) AS sede, min(fa.fecha_aviso) AS inicio,
      (SELECT json_agg(json_build_object(
                'fase', x.fase, 'orden', x.orden_fase,
                'aviso', to_char(x.fecha_aviso AT TIME ZONE 'Europe/Madrid', 'YYYY-MM-DD"T"HH24:MI'),
                'evento', to_char(x.fecha_evento AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'),
                'titulo', split_part(x.titulo, ' · ', 1), 'grav', x.soc_peligrosidad, 'id', x.id_alerta_soc)
              ORDER BY x.fecha_aviso)
       FROM v_fases_alertas x WHERE x.victima = fa.victima) AS eventos,
      (SELECT json_build_object('estado', b.estado, 'origen', b.origen, 'regla', b.regla, 'confirmado', b.confirmado)
       FROM v_bloqueos_activos b WHERE b.tipo = 'USUARIO' AND b.valor = fa.victima) AS bloqueo
    FROM v_fases_alertas fa WHERE fa.victima ILIKE %(patron)s GROUP BY fa.victima) v),
 'auto06', (SELECT json_agg(json_build_object('usuario', valor_objetivo, 'decision', decision))
            FROM decisiones_bloqueo_auto WHERE regla_id = 'AUTO-06'),
 'prediccion', (SELECT row_to_json(p) FROM (
    SELECT min_medios_entre_avisos, to_char(siguiente_victima_estimada_aviso, 'HH24:MI') AS siguiente
    FROM v_cadena_prediccion) p),
 'cola', (SELECT json_build_object('pendientes', count(*) FILTER (WHERE estado = 'PENDIENTE'),
                                   'omitidas', count(*) FILTER (WHERE estado = 'OMITIDA'),
                                   'ejecutadas', count(*) FILTER (WHERE estado = 'EJECUTADA'))
          FROM acciones_bloqueo WHERE NOT simulacion),
 'demo', (SELECT count(*) FROM acciones_bloqueo WHERE simulacion AND accion = 'BLOQUEAR' AND estado = 'EJECUTADA')
)
"""


def main() -> None:
    with psycopg.connect(sslmode=os.getenv("PGSSLMODE", "require"), connect_timeout=15,
                         application_name="infografia-cadena") as conn:
        datos = conn.execute(SQL, {"patron": "%moreno@%"}).fetchone()[0]
    plantilla = (DIR / "plantilla_cadena.html").read_text(encoding="utf-8")
    html = plantilla.replace("__DATA__", json.dumps(datos, ensure_ascii=False).replace("</", "<\\/"))
    (DIR / "cadena_moreno.html").write_text(html, encoding="utf-8")
    print(f"cadena_moreno.html: {len(datos['victimas'])} víctimas, cola {datos['cola']}, demo {datos['demo']}")


if __name__ == "__main__":
    main()
