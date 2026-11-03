-- ============================================================================
-- 002_vistas_dashboard.sql — Vistas para el cuadro de mando (el frontend no lleva lógica)
-- Todas excluyen las alertas duplicadas (es_duplicada = FALSE).
-- ============================================================================

CREATE OR REPLACE VIEW v_incibe_taxonomia AS
SELECT c.clase_id, c.nombre AS clase, t.tipo_id, t.nombre AS tipo, c.orden
FROM incibe_clases c
LEFT JOIN incibe_tipos t ON t.clase_id = c.clase_id
ORDER BY c.orden, t.nombre;

CREATE OR REPLACE VIEW v_alertas AS
SELECT a.alerta_id,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AS fecha,
       a.fecha_hora_evento, a.fecha_hora_correo,
       a.soc_prioridad, a.soc_peligrosidad,
       a.titulo, a.asunto_correo, a.remitente_correo,
       a.fuente_herramienta, a.equipo_afectado, a.ip_afectada, a.usuario_implicado,
       a.incibe_clase_id, c.nombre AS clase_incibe, a.incibe_tipo_id, t.nombre AS tipo_incibe,
       a.justificacion_categoria, a.metodo_categorizacion, a.impacto_incibe, a.peligrosidad_incibe,
       a.estado, a.es_sospechosa, a.motivo_sospecha,
       a.revisado_por_humano, a.usuario_analista,
       (SELECT count(*) FROM alertas d WHERE d.alerta_original_id = a.alerta_id) AS num_duplicados,
       a.correo_id, a.id_mensaje_correo
FROM alertas a
LEFT JOIN incibe_clases c ON c.clase_id = a.incibe_clase_id
LEFT JOIN incibe_tipos  t ON t.tipo_id  = a.incibe_tipo_id
WHERE NOT a.es_duplicada;

CREATE OR REPLACE VIEW v_stats_clase AS
SELECT coalesce(clase_incibe, 'Sin clasificar') AS clase, incibe_clase_id, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_prioridad_peligrosidad AS
SELECT soc_prioridad, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_fuente AS
SELECT coalesce(fuente_herramienta, 'Desconocida') AS fuente, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_estado AS
SELECT estado, count(*) AS total
FROM v_alertas
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_equipos AS
SELECT lower(equipo_afectado) AS equipo, count(*) AS total, max(fecha) AS ultima,
       max(soc_peligrosidad) AS peligrosidad_max,
       array_agg(DISTINCT clase_incibe) FILTER (WHERE clase_incibe IS NOT NULL) AS clases
FROM v_alertas
WHERE equipo_afectado IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_usuarios AS
SELECT lower(usuario_implicado) AS usuario, count(*) AS total, max(fecha) AS ultima,
       max(soc_peligrosidad) AS peligrosidad_max,
       array_agg(DISTINCT clase_incibe) FILTER (WHERE clase_incibe IS NOT NULL) AS clases
FROM v_alertas
WHERE usuario_implicado IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_ips AS
SELECT ip_afectada AS ip, count(*) AS total, max(fecha) AS ultima,
       array_agg(DISTINCT lower(equipo_afectado)) FILTER (WHERE equipo_afectado IS NOT NULL) AS equipos
FROM v_alertas
WHERE ip_afectada IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_timeline AS
SELECT date_trunc('hour', fecha) AS hora, coalesce(clase_incibe, 'Sin clasificar') AS clase, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

-- KPIs para la cabecera del dashboard y el análisis de ROI (incluye ruido y duplicados)
CREATE OR REPLACE VIEW v_kpis AS
SELECT (SELECT count(*) FROM bandeja_entrada)                                   AS correos_recibidos,
       (SELECT count(*) FROM alertas)                                           AS alertas_total,
       (SELECT count(*) FROM alertas WHERE es_duplicada)                        AS duplicadas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada)                    AS alertas_unicas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado = 'FALSA_ALARMA') AS falsas_alarmas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado = 'NO_SOC')       AS no_soc,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado IN ('NUEVA','EN_REVISION')) AS pendientes,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND soc_prioridad = 'P1')    AS p1,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND incibe_clase_id IS NULL) AS sin_clasificar,
       (SELECT count(*) FROM alertas WHERE es_sospechosa)
         + (SELECT count(*) FROM correos_malformados WHERE es_sospechoso)       AS sospechosos,
       (SELECT count(*) FROM correos_malformados)                               AS malformados,
       (SELECT count(*) FROM correos_malformados WHERE estado = 'PENDIENTE_REVISION') AS malformados_pendientes,
       (SELECT count(*) FROM acciones_bloqueo WHERE accion = 'BLOQUEAR' AND exito)     AS bloqueos_ok;
