-- ============================================================================
-- 015_outlook_aviso_ia_externo.sql — Avisos externos que solo mencionan una herramienta de IA → «06 No SOC»
--
-- Despliegue de BD-011: el aviso de inicio de sesión de noreply@tm.openai.com caía en «05 Cuarentena» por
-- "Menciona herramientas de IA o prompts" (nombra ChatGPT), cuando lo esperado es «06 No SOC».
-- Se relaja SOLO ese motivo, y solo si el remitente es externo, el correo tiene cabeceras de transporte, no
-- es una alerta del SOC y no intenta imponer una clasificación. "Pide ignorar instrucciones" y "Texto
-- dirigido a una IA" siguen yendo a cuarentena siempre. Misma vista que la 011 (mismas columnas). Idempotente.
-- ============================================================================

CREATE OR REPLACE VIEW v_outlook_destino AS
WITH cfg AS (SELECT * FROM config_outlook WHERE id = 1),
base AS (
    SELECT b.correo_id, b.fecha_hora_correo, lower(btrim(b.remitente_correo)) AS remitente,
           b.asunto_correo,
           -- Identificador para encontrar el correo en Outlook (InternetMessageId completo si lo guardó la ingesta)
           coalesce(nullif(b.cabeceras ->> 'original_message_id', ''), b.id_mensaje_correo) AS id_outlook,
           a.alerta_id, a.referencia_soc, a.id_alerta_soc, a.soc_peligrosidad, a.criticidad_cuerpo,
           a.incibe_clase_id, a.estado::text AS estado_alerta, a.es_duplicada, a.id_solicitud,
           coalesce(cardinality(a.inconsistencias), 0) AS num_inconsistencias,
           m.descarte_id,
           -- procesar_correo() marca como sospechoso a todo remitente fuera de remitentes_confianza; para ordenar
           -- el buzón solo cuentan los motivos reales (instrucciones a una IA, clasificación impuesta...)
           nullif(btrim(regexp_replace(coalesce(a.motivo_sospecha, m.motivo_sospecha, ''),
                                       'Remitente fuera de la lista de confianza \([^)]*\)', '', 'g'), '; '), '') AS sospecha_real,
           coalesce(au.verificada, FALSE) AS verificada, au.motivo AS motivo_autenticidad,
           -- Un EML sin ninguna cabecera Received no ha pasado por un servidor de correo: inyectado o manipulado
           (b.eml_raw IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM cabeceras_eml(b.correo_id) h WHERE h.nombre = 'received')) AS sin_transporte,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_directrices) x) AS es_director,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_soc) x) AS es_soc,
           -- motivo_sospecha_ia() solo devuelve el primer motivo y mira "menciona IA" antes que "impone clasificación":
           -- se vuelve a comprobar aquí para no relajar un correo que haga las dos cosas (015)
           lower(coalesce(b.asunto_correo, '') || ' ' || texto_plano(b.cuerpo_correo_raw))
               ~ '(clasifica|marca|categoriza|classify|mark).{0,40}(como|as) (falso positivo|false positive|no_soc|informativ|benign|leg[ií]tim)'
               AS impone_clasificacion
    FROM bandeja_entrada b
    LEFT JOIN alertas a ON a.correo_id = b.correo_id
    LEFT JOIN correos_malformados m ON m.correo_id = b.correo_id AND a.alerta_id IS NULL
    LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE
),
clasif AS (
    SELECT base.*,
           -- Un aviso externo que solo nombra una herramienta de IA (p. ej. el inicio de sesión de OpenAI) no es
           -- sospechoso: pasó por servidores de correo, no imita una alerta del SOC y no da órdenes (015)
           sospecha_real IS NOT NULL
               AND NOT (sospecha_real = 'Menciona herramientas de IA o prompts'
                        AND motivo_autenticidad LIKE 'Remitente externo%'
                        AND NOT sin_transporte
                        AND alerta_id IS NULL
                        AND NOT impone_clasificacion) AS marcado_sospechoso,
           alerta_id IS NOT NULL AND NOT es_soc AND NOT es_director AS formato_soc_suplantado,
           CASE WHEN verificada THEN 'VERIFICADO'
                WHEN motivo_autenticidad LIKE 'Remitente externo%' THEN 'EXTERNO'
                WHEN motivo_autenticidad LIKE 'Sin %' OR motivo_autenticidad LIKE 'Falta %'
                     OR motivo_autenticidad LIKE 'Correo interno sin%' THEN 'SIN_DATOS'
                ELSE 'FALLIDA' END AS autenticidad,
           alerta_id IS NOT NULL AND (
               id_solicitud IS NOT NULL
               OR asunto_correo ~* '\mSOL-[0-9]+'
               OR plegar(asunto_correo) ~ 'solicitud (de )?(bloqueo|liberacion|desbloqueo)') AS es_solicitud,
           plegar(soc_peligrosidad::text) IN ('critico', 'alto')
               OR plegar(criticidad_cuerpo) ~ '^(critic|alt)' AS es_grave,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND ba.confirmado) AS bloqueo_confirmado,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND NOT ba.confirmado) AS bloqueo_en_curso,
           EXISTS (SELECT 1 FROM decisiones_bloqueo_auto d WHERE d.alerta_id = base.alerta_id AND d.decision = 'RECOMENDAR') AS recomendado
    FROM base
),
destino AS (
    SELECT clasif.*,
           CASE
               WHEN alerta_id IS NULL AND descarte_id IS NULL THEN NULL           -- aún sin procesar: se queda en la Bandeja
               WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte THEN 'CUARENTENA'
               WHEN es_director THEN 'DIRECTRICES'
               WHEN formato_soc_suplantado THEN 'CUARENTENA'
               WHEN autenticidad = 'EXTERNO' THEN 'NO_SOC'
               WHEN descarte_id IS NOT NULL AND es_soc THEN 'SOC_REVISION'
               WHEN descarte_id IS NOT NULL THEN 'NO_SOC'
               WHEN es_solicitud THEN 'SOLICITUDES'
               WHEN es_duplicada OR estado_alerta = 'FALSA_ALARMA' OR soc_peligrosidad::text = 'INFORMATIVO' THEN 'RUIDO'
               WHEN estado_alerta = 'NO_SOC' THEN 'NO_SOC'
               WHEN estado_alerta = 'CERRADA' THEN 'SOC_CERRADAS'
               WHEN es_grave THEN 'SOC_CRITICAS'
               ELSE 'SOC_MEDIAS'
           END AS carpeta_codigo,
           array_remove(ARRAY[
               CASE WHEN soc_peligrosidad IS NOT NULL THEN 'GRAVEDAD:' || soc_peligrosidad::text END,
               CASE WHEN incibe_clase_id IS NOT NULL THEN 'INCIBE:' || incibe_clase_id END,
               CASE WHEN es_director THEN 'SENAL:DIRECTRIZ' END,
               CASE WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte OR formato_soc_suplantado THEN 'SENAL:SOSPECHOSO'
                    WHEN autenticidad = 'VERIFICADO' THEN 'SENAL:VERIFICADO'
                    WHEN autenticidad = 'EXTERNO' THEN 'SENAL:EXTERNO'
                    ELSE 'SENAL:NO_VERIFICADO' END,
               CASE WHEN num_inconsistencias > 0 THEN 'SENAL:INCONSISTENTE' END,
               CASE WHEN es_duplicada THEN 'SENAL:DUPLICADO' END,
               CASE WHEN es_solicitud THEN 'SENAL:SOLICITUD' END,
               CASE WHEN estado_alerta = 'FALSA_ALARMA' THEN 'SENAL:FALSA_ALARMA' END,
               CASE WHEN (descarte_id IS NOT NULL AND es_soc) OR estado_alerta = 'EN_REVISION' THEN 'SENAL:REVISION' END,
               CASE WHEN bloqueo_confirmado THEN 'SENAL:BLOQUEO'
                    WHEN bloqueo_en_curso THEN 'SENAL:BLOQUEO_PENDIENTE'
                    WHEN recomendado THEN 'SENAL:RECOMENDACION' END,
               CASE WHEN (descarte_id IS NOT NULL AND NOT es_soc AND NOT es_director) OR estado_alerta = 'NO_SOC'
                         OR autenticidad = 'EXTERNO' THEN 'SENAL:NO_SOC' END
           ], NULL) AS claves
    FROM clasif
)
SELECT d.correo_id, d.fecha_hora_correo, d.remitente, d.id_outlook, d.alerta_id,
       coalesce(d.referencia_soc, d.id_alerta_soc) AS referencia,
       d.carpeta_codigo, c.ruta AS carpeta_ruta,
       coalesce((SELECT array_agg(oc.nombre ORDER BY oc.orden)
                 FROM outlook_categorias oc
                 WHERE oc.grupo || ':' || oc.clave = ANY (d.claves)), '{}') AS categorias,
       CASE d.carpeta_codigo
           WHEN 'CUARENTENA'   THEN 'Sospechoso: ' || coalesce(d.sospecha_real,
                                                               CASE WHEN d.sin_transporte THEN 'sin cabeceras de transporte (posible inyección)' END,
                                                               CASE WHEN d.autenticidad = 'FALLIDA' THEN d.motivo_autenticidad END,
                                                               CASE WHEN d.formato_soc_suplantado THEN 'formato de alerta SOC enviado por ' || d.remitente || ', que no es el SOC' END,
                                                               'marcado por las reglas de detección')
           WHEN 'DIRECTRICES'  THEN 'Remitente de directrices (' || d.autenticidad || ')'
           WHEN 'NO_SOC'       THEN 'No es una alerta del SOC (' || d.autenticidad || ')'
           WHEN 'SOC_REVISION' THEN 'Correo del SOC sin formato reconocible: revisión manual'
           WHEN 'SOLICITUDES'  THEN 'Petición de bloqueo o liberación: no se ejecuta desde el correo'
           WHEN 'RUIDO'        THEN CASE WHEN d.es_duplicada THEN 'Duplicado de otra alerta'
                                         WHEN d.estado_alerta = 'FALSA_ALARMA' THEN 'Falsa alarma'
                                         ELSE 'Alerta informativa' END
           WHEN 'SOC_CERRADAS' THEN 'Alerta cerrada'
           WHEN 'SOC_CRITICAS' THEN 'Alerta crítica o alta pendiente'
           WHEN 'SOC_MEDIAS'   THEN 'Alerta media o baja'
       END AS motivo,
       md5(coalesce(d.carpeta_codigo, '') || '|' || array_to_string(ARRAY(SELECT x FROM unnest(d.claves) x ORDER BY x), ',')) AS huella
FROM destino d
LEFT JOIN outlook_carpetas c ON c.codigo = d.carpeta_codigo;
