-- ============================================================================
-- 011_organizacion_outlook.sql — El buzón de Outlook se ordena según la base de datos (decisión D-008)
--
-- Petición: que la bandeja de entrada esté organizada con carpetas y etiquetas según el correo que llega.
-- Diseño:
--   * CARPETA  = qué hay que hacer con el correo (una por correo): directrices, SOC por urgencia,
--                solicitudes, ruido, cuarentena, no SOC.
--   * ETIQUETAS (categorías de Outlook, varias por correo) = qué es: gravedad, clase INCIBE y señales
--                (verificado, sospechoso, duplicado, inconsistente, bloqueo...).
--   * Lo decide SOLO la base de datos (misma clasificación que el cuadro de mando). El script
--     soc/outlook_organizar.py lo aplica con Microsoft Graph y registra cada cambio.
--   * Solo se mueven correos que ya están guardados en bandeja_entrada: el flujo de Power Automate
--     que se dispara en la Bandeja de entrada nunca pierde un correo.
-- Todo es configuración editable (nombres, colores, remitentes). Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CONFIGURACIÓN
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_outlook (
    id                      SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    organizacion_activa     BOOLEAN NOT NULL DEFAULT TRUE,       -- interruptor general desde la BD
    remitentes_directrices  TEXT[]  NOT NULL DEFAULT '{dirti@sampol.com}',
    remitentes_soc          TEXT[]  NOT NULL DEFAULT '{soc-hackaton@sampol.com}',
    fecha_actualizacion     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO config_outlook (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Carpetas: ruta relativa a la Bandeja de entrada ("/" separa subcarpetas)
CREATE TABLE IF NOT EXISTS outlook_carpetas (
    codigo      VARCHAR(30) PRIMARY KEY,
    ruta        VARCHAR(200) NOT NULL UNIQUE,
    descripcion TEXT NOT NULL,
    orden       SMALLINT NOT NULL
);
INSERT INTO outlook_carpetas (codigo, ruta, descripcion, orden) VALUES
    ('DIRECTRICES',  '01 Directrices',             'Correos del director de TI', 1),
    ('SOC_CRITICAS', '02 SOC/Críticas y altas',    'Alertas del SOC críticas o altas pendientes de acción', 2),
    ('SOC_MEDIAS',   '02 SOC/Medias y bajas',      'Alertas del SOC de gravedad media o baja', 3),
    ('SOC_REVISION', '02 SOC/Revisión manual',     'Correos del SOC que el sistema no pudo interpretar', 4),
    ('SOC_CERRADAS', '02 SOC/Cerradas',            'Alertas del SOC cerradas', 5),
    ('SOLICITUDES',  '03 Solicitudes (SOL)',       'Peticiones de bloqueo o liberación: nunca se ejecutan solas', 6),
    ('RUIDO',        '04 Ruido',                   'Duplicados, informativos y falsas alarmas', 7),
    ('CUARENTENA',   '05 Cuarentena',              'Correos sospechosos, manipulados o con autenticidad fallida', 8),
    ('NO_SOC',       '06 No SOC',                  'Organización, avisos de servicios y otros', 9)
ON CONFLICT (codigo) DO NOTHING;

-- Etiquetas (categorías de Outlook). color = preset de Microsoft Graph (preset0 rojo ... preset24)
CREATE TABLE IF NOT EXISTS outlook_categorias (
    grupo   VARCHAR(10) NOT NULL CHECK (grupo IN ('GRAVEDAD', 'INCIBE', 'SENAL')),
    clave   VARCHAR(50) NOT NULL,
    nombre  VARCHAR(60) NOT NULL UNIQUE,
    color   VARCHAR(10) NOT NULL CHECK (color ~ '^preset([0-9]|1[0-9]|2[0-4])$'),
    orden   SMALLINT NOT NULL,
    PRIMARY KEY (grupo, clave)
);
INSERT INTO outlook_categorias (grupo, clave, nombre, color, orden) VALUES
    ('GRAVEDAD', 'CRITICO',     'Gravedad: Crítica',     'preset0',  1),
    ('GRAVEDAD', 'ALTO',        'Gravedad: Alta',        'preset1',  2),
    ('GRAVEDAD', 'MEDIO',       'Gravedad: Media',       'preset3',  3),
    ('GRAVEDAD', 'BAJO',        'Gravedad: Baja',        'preset4',  4),
    ('GRAVEDAD', 'INFORMATIVO', 'Gravedad: Informativa', 'preset12', 5),
    ('SENAL', 'DIRECTRIZ',         'Directriz',                 'preset10', 30),
    ('SENAL', 'VERIFICADO',        'Remitente verificado',      'preset19', 31),
    ('SENAL', 'NO_VERIFICADO',     'Remitente sin verificar',   'preset13', 32),
    ('SENAL', 'SOSPECHOSO',        'Sospechoso',                'preset15', 33),
    ('SENAL', 'EXTERNO',           'Remitente externo',         'preset11', 34),
    ('SENAL', 'INCONSISTENTE',     'Inconsistente',             'preset2',  35),
    ('SENAL', 'DUPLICADO',         'Duplicado',                 'preset13', 36),
    ('SENAL', 'SOLICITUD',         'Solicitud: no ejecutar',    'preset17', 37),
    ('SENAL', 'FALSA_ALARMA',      'Falsa alarma',              'preset12', 38),
    ('SENAL', 'REVISION',          'Pendiente de revisión',     'preset18', 39),
    ('SENAL', 'BLOQUEO_PENDIENTE', 'Bloqueo en curso',          'preset16', 40),
    ('SENAL', 'BLOQUEO',           'Bloqueo aplicado',          'preset20', 41),
    ('SENAL', 'RECOMENDACION',     'Recomendación de bloqueo',  'preset21', 42),
    ('SENAL', 'NO_SOC',            'No SOC',                    'preset14', 43)
ON CONFLICT (grupo, clave) DO NOTHING;

-- Una etiqueta por clase INCIBE, con el nombre del catálogo
INSERT INTO outlook_categorias (grupo, clave, nombre, color, orden)
SELECT 'INCIBE', c.clase_id, left('INCIBE: ' || c.nombre, 60), v.color, 10 + coalesce(c.orden, 0)
FROM incibe_clases c
JOIN (VALUES ('CONTENIDO_ABUSIVO', 'preset9'), ('CONTENIDO_DANINO', 'preset24'), ('OBTENCION_INFORMACION', 'preset5'),
             ('INTENTO_INTRUSION', 'preset7'), ('INTRUSION', 'preset22'), ('DISPONIBILIDAD', 'preset6'),
             ('COMPROMISO_INFORMACION', 'preset23'), ('FRAUDE', 'preset8'), ('VULNERABLE', 'preset21'),
             ('OTROS', 'preset12')) AS v(clase_id, color) ON v.clase_id = c.clase_id
ON CONFLICT (grupo, clave) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. REGISTRO DE LO APLICADO EN OUTLOOK (auditoría y control de cambios)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outlook_sincronizacion (
    correo_id        UUID PRIMARY KEY REFERENCES bandeja_entrada(correo_id),
    carpeta_codigo   VARCHAR(30) REFERENCES outlook_carpetas(codigo),
    categorias       TEXT[] NOT NULL DEFAULT '{}',
    huella           VARCHAR(32) NOT NULL,            -- md5(carpeta + etiquetas): detecta cambios
    graph_message_id TEXT,
    estado           VARCHAR(15) NOT NULL CHECK (estado IN ('APLICADO', 'NO_ENCONTRADO', 'ERROR')),
    detalle          TEXT,
    intentos         INTEGER NOT NULL DEFAULT 1,
    fecha            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outlook_sinc_estado ON outlook_sincronizacion (estado, fecha);

CREATE OR REPLACE FUNCTION registrar_sincronizacion_outlook(
    p_correo_id UUID, p_huella TEXT, p_carpeta TEXT, p_categorias TEXT[],
    p_graph_id TEXT, p_estado TEXT, p_detalle TEXT)
RETURNS VOID AS $$
    INSERT INTO outlook_sincronizacion
        (correo_id, carpeta_codigo, categorias, huella, graph_message_id, estado, detalle, intentos, fecha)
    VALUES (p_correo_id, p_carpeta, coalesce(p_categorias, '{}'), p_huella, p_graph_id, p_estado, left(p_detalle, 1000), 1, now())
    ON CONFLICT (correo_id) DO UPDATE SET
        carpeta_codigo   = EXCLUDED.carpeta_codigo,
        categorias       = EXCLUDED.categorias,
        graph_message_id = coalesce(EXCLUDED.graph_message_id, outlook_sincronizacion.graph_message_id),
        estado           = EXCLUDED.estado,
        detalle          = EXCLUDED.detalle,
        intentos         = CASE WHEN outlook_sincronizacion.huella = EXCLUDED.huella AND EXCLUDED.estado <> 'APLICADO'
                                THEN outlook_sincronizacion.intentos + 1 ELSE 1 END,
        huella           = EXCLUDED.huella,
        fecha            = now();
$$ LANGUAGE sql;

-- ----------------------------------------------------------------------------
-- 3. DESTINO DE CADA CORREO
-- ----------------------------------------------------------------------------
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
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_soc) x) AS es_soc
    FROM bandeja_entrada b
    LEFT JOIN alertas a ON a.correo_id = b.correo_id
    LEFT JOIN correos_malformados m ON m.correo_id = b.correo_id AND a.alerta_id IS NULL
    LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE
),
clasif AS (
    SELECT base.*,
           sospecha_real IS NOT NULL AS marcado_sospechoso,
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

-- Lo que el script tiene que aplicar: correos nuevos, con cambios, o con errores que toca reintentar
CREATE OR REPLACE VIEW v_outlook_pendientes AS
SELECT d.*
FROM v_outlook_destino d
LEFT JOIN outlook_sincronizacion s ON s.correo_id = d.correo_id
WHERE d.carpeta_codigo IS NOT NULL
  AND (s.correo_id IS NULL
       OR s.huella <> d.huella
       OR (s.estado <> 'APLICADO' AND s.intentos < 6 AND s.fecha < now() - interval '10 minutes'))
ORDER BY d.fecha_hora_correo;

-- Resumen por carpeta (dashboard y comprobaciones)
CREATE OR REPLACE VIEW v_outlook_resumen AS
SELECT c.orden, c.codigo, c.ruta,
       count(d.correo_id)                                       AS correos,
       count(s.correo_id) FILTER (WHERE s.estado = 'APLICADO' AND s.huella = d.huella) AS aplicados,
       count(d.correo_id) FILTER (WHERE s.correo_id IS NULL OR s.huella <> d.huella OR s.estado <> 'APLICADO') AS pendientes
FROM outlook_carpetas c
LEFT JOIN v_outlook_destino d ON d.carpeta_codigo = c.codigo
LEFT JOIN outlook_sincronizacion s ON s.correo_id = d.correo_id
GROUP BY c.orden, c.codigo, c.ruta;
