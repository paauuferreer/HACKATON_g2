-- ============================================================================
-- 004_vistas_formato_real.sql — Vistas con los campos del formato real (sede, IDs, inconsistencias)
-- CREATE OR REPLACE VIEW solo permite añadir columnas al final.
-- ============================================================================

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
       a.correo_id, a.id_mensaje_correo,
       -- añadidas en 004
       a.sede, a.regla_deteccion, a.criticidad_cuerpo, a.ip_raw,
       a.id_alerta_soc, a.referencia_soc, a.id_solicitud,
       a.fecha_ultimo_evento, a.fecha_emision,
       a.inconsistencias, a.regla_id, a.remitente_confianza
FROM alertas a
LEFT JOIN incibe_clases c ON c.clase_id = a.incibe_clase_id
LEFT JOIN incibe_tipos  t ON t.tipo_id  = a.incibe_tipo_id
WHERE NOT a.es_duplicada;

CREATE OR REPLACE VIEW v_stats_sede AS
SELECT coalesce(sede, 'Sin sede') AS sede, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_tipo AS
SELECT coalesce(clase_incibe, 'Sin clasificar') AS clase, coalesce(tipo_incibe, '—') AS tipo, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

-- Alertas que el analista debería mirar dos veces (trampas del buzón)
CREATE OR REPLACE VIEW v_inconsistencias AS
SELECT alerta_id, fecha, referencia_soc, titulo, soc_prioridad, soc_peligrosidad, criticidad_cuerpo,
       unnest(inconsistencias) AS inconsistencia
FROM v_alertas
WHERE cardinality(inconsistencias) > 0
UNION ALL
SELECT alerta_id, fecha, referencia_soc, titulo, soc_prioridad, soc_peligrosidad, criticidad_cuerpo,
       'Sospechosa: ' || motivo_sospecha
FROM v_alertas
WHERE es_sospechosa;

-- Solicitudes de bloqueo / liberación pendientes de decidir (alimentan la automatización con la API)
CREATE OR REPLACE VIEW v_solicitudes AS
SELECT alerta_id, fecha_hora_correo, id_solicitud, titulo, usuario_implicado, ip_afectada, estado,
       remitente_correo, remitente_confianza, es_sospechosa, motivo_sospecha
FROM v_alertas
WHERE id_solicitud IS NOT NULL
ORDER BY fecha_hora_correo;
