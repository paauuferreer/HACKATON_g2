-- ============================================================================
-- 018 · v_kpis: bloqueos_ok no cuenta las filas de la demo (simulacion = TRUE)
-- La vista de 002 contaba los 13 bloqueos contra el simulador local como bloqueos reales.
-- Mismas columnas y mismo orden (CREATE OR REPLACE VIEW). Idempotente.
-- ============================================================================

CREATE OR REPLACE VIEW v_kpis AS
SELECT ( SELECT count(*) AS count
           FROM bandeja_entrada) AS correos_recibidos,
    ( SELECT count(*) AS count
           FROM alertas) AS alertas_total,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE alertas.es_duplicada) AS duplicadas,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada) AS alertas_unicas,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada AND alertas.estado = 'FALSA_ALARMA'::estado_alerta_enum) AS falsas_alarmas,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada AND alertas.estado = 'NO_SOC'::estado_alerta_enum) AS no_soc,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada AND (alertas.estado = ANY (ARRAY['NUEVA'::estado_alerta_enum, 'EN_REVISION'::estado_alerta_enum]))) AS pendientes,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada AND alertas.soc_prioridad = 'P1'::prioridad_soc_enum) AS p1,
    ( SELECT count(*) AS count
           FROM alertas
          WHERE NOT alertas.es_duplicada AND alertas.incibe_clase_id IS NULL) AS sin_clasificar,
    (( SELECT count(*) AS count
           FROM alertas
          WHERE alertas.es_sospechosa)) + (( SELECT count(*) AS count
           FROM correos_malformados
          WHERE correos_malformados.es_sospechoso)) AS sospechosos,
    ( SELECT count(*) AS count
           FROM correos_malformados) AS malformados,
    ( SELECT count(*) AS count
           FROM correos_malformados
          WHERE correos_malformados.estado = 'PENDIENTE_REVISION'::estado_malformado_enum) AS malformados_pendientes,
    ( SELECT count(*) AS count
           FROM acciones_bloqueo
          WHERE acciones_bloqueo.accion::text = 'BLOQUEAR'::text AND acciones_bloqueo.exito
            AND NOT acciones_bloqueo.simulacion) AS bloqueos_ok;
