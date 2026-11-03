-- ============================================================================
-- 006_analitica_temporal.sql — Análisis por horas, franjas, semanas, meses, años y contexto geopolítico
--
-- Todas las horas se expresan en Europe/Madrid (hora de la empresa).
-- Columnas comunes de las vistas:
--   total   = alertas únicas (sin duplicados): mide CARGA de trabajo, el ruido también cuesta revisarlo
--   reales  = sin FALSA_ALARMA ni NO_SOC: mide AMENAZA
--   criticas, p1 = alertas únicas con peligrosidad CRITICO / prioridad P1
-- Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. FRANJAS HORARIAS Y PARÁMETROS DE NEGOCIO (los costes los rellena Administración)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS franjas_horarias (
    franja        VARCHAR(30) PRIMARY KEY,
    descripcion   TEXT NOT NULL,
    orden         SMALLINT NOT NULL,
    coste_hora_eur NUMERIC(8, 2),               -- NULL hasta tener el dato real
    es_hipotesis  BOOLEAN NOT NULL DEFAULT TRUE,
    fuente        TEXT
);
INSERT INTO franjas_horarias (franja, descripcion, orden) VALUES
    ('LABORAL',               'Lunes a viernes laborables, 08:00-17:59', 1),
    ('GUARDIA_TARDE',         'Lunes a viernes laborables, 18:00-21:59', 2),
    ('FIN_DE_SEMANA_FESTIVO', 'Sábados, domingos y festivos, 08:00-21:59', 3),
    ('GUARDIA_NOCHE',         'Todos los días, 22:00-07:59', 4)
ON CONFLICT (franja) DO NOTHING;

CREATE TABLE IF NOT EXISTS festivos (
    fecha  DATE PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL
);

-- Valores para el ROI (clave → valor). Cada cifra indica si es hipótesis y de dónde sale.
CREATE TABLE IF NOT EXISTS parametros_negocio (
    clave        VARCHAR(50) PRIMARY KEY,
    valor        NUMERIC(12, 2),
    unidad       VARCHAR(30) NOT NULL,
    descripcion  TEXT NOT NULL,
    es_hipotesis BOOLEAN NOT NULL DEFAULT TRUE,
    fuente       TEXT
);
INSERT INTO parametros_negocio (clave, valor, unidad, descripcion) VALUES
    ('minutos_revision_manual', NULL, 'min/alerta', 'Tiempo medio que tarda hoy un analista en revisar una alerta a mano'),
    ('minutos_revision_sistema', NULL, 'min/alerta', 'Tiempo medio de revisión con nuestra solución')
ON CONFLICT (clave) DO NOTHING;

CREATE OR REPLACE FUNCTION franja_horaria(p_ts TIMESTAMP WITH TIME ZONE) RETURNS VARCHAR AS $$
DECLARE
    v_local TIMESTAMP := p_ts AT TIME ZONE 'Europe/Madrid';
    v_hora  INTEGER   := extract(hour FROM v_local);
BEGIN
    IF p_ts IS NULL THEN
        RETURN NULL;
    ELSIF v_hora >= 22 OR v_hora < 8 THEN
        RETURN 'GUARDIA_NOCHE';
    ELSIF extract(isodow FROM v_local) >= 6
          OR EXISTS (SELECT 1 FROM festivos WHERE fecha = v_local::date) THEN
        RETURN 'FIN_DE_SEMANA_FESTIVO';
    ELSIF v_hora >= 18 THEN
        RETURN 'GUARDIA_TARDE';
    ELSE
        RETURN 'LABORAL';
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- ----------------------------------------------------------------------------
-- 2. BASE COMÚN: una fila por alerta (incluye duplicadas para poder contarlas)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_alertas_tiempo AS
SELECT a.alerta_id,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo)                            AS fecha,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AT TIME ZONE 'Europe/Madrid' AS fecha_local,
       franja_horaria(coalesce(a.fecha_hora_evento, a.fecha_hora_correo))            AS franja,
       a.es_duplicada,
       NOT a.es_duplicada AND a.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')             AS es_real,
       a.estado, a.soc_prioridad, a.soc_peligrosidad, a.incibe_clase_id, a.es_sospechosa,
       a.fuente_herramienta, a.sede
FROM alertas a;

-- ----------------------------------------------------------------------------
-- 3. MAPA DE CALOR día de la semana × hora (Europe/Madrid)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_heatmap_dia_hora AS
SELECT d.dia_semana, d.nombre_dia, h.hora,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)                                   AS total,
       count(t.alerta_id) FILTER (WHERE t.es_real)                                            AS reales,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO') AS criticas,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_prioridad = 'P1')         AS p1
FROM (VALUES (1, 'Lunes'), (2, 'Martes'), (3, 'Miércoles'), (4, 'Jueves'),
             (5, 'Viernes'), (6, 'Sábado'), (7, 'Domingo')) d(dia_semana, nombre_dia)
CROSS JOIN generate_series(0, 23) h(hora)
LEFT JOIN v_alertas_tiempo t
       ON extract(isodow FROM t.fecha_local) = d.dia_semana
      AND extract(hour   FROM t.fecha_local) = h.hora
GROUP BY d.dia_semana, d.nombre_dia, h.hora;

-- ----------------------------------------------------------------------------
-- 4. CARGA Y COSTE POR FRANJA HORARIA (coste NULL hasta que Administración dé las cifras)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_stats_franja AS
SELECT f.orden, f.franja, f.descripcion, f.coste_hora_eur, f.es_hipotesis,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)                                    AS total,
       count(t.alerta_id) FILTER (WHERE t.es_real)                                             AS reales,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO') AS criticas,
       count(t.alerta_id) FILTER (WHERE t.es_duplicada)                                        AS duplicadas,
       round(count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)
             * (SELECT valor FROM parametros_negocio WHERE clave = 'minutos_revision_manual') / 60.0
             * f.coste_hora_eur, 2)                                                            AS coste_manual_eur
FROM franjas_horarias f
LEFT JOIN v_alertas_tiempo t ON t.franja = f.franja
GROUP BY f.orden, f.franja, f.descripcion, f.coste_hora_eur, f.es_hipotesis;

-- ----------------------------------------------------------------------------
-- 5. ESTADÍSTICAS POR PERIODO: hora, día, semana, mes y año (exportables tal cual)
--    Filtrar por granularidad: WHERE granularidad = 'mes'
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_stats_periodo AS
WITH g(granularidad, unidad) AS (
    VALUES ('hora', 'hour'), ('dia', 'day'), ('semana', 'week'), ('mes', 'month'), ('anio', 'year'))
SELECT g.granularidad,
       date_trunc(g.unidad, t.fecha_local)                                                     AS periodo,
       count(*) FILTER (WHERE NOT t.es_duplicada)                                              AS total,
       count(*) FILTER (WHERE t.es_real)                                                       AS reales,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO')           AS criticas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'ALTO')              AS altas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_prioridad = 'P1')                   AS p1,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.estado = 'FALSA_ALARMA')                AS falsas_alarmas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.estado = 'NO_SOC')                      AS no_soc,
       count(*) FILTER (WHERE t.es_sospechosa)                                                 AS sospechosas,
       count(*) FILTER (WHERE t.es_duplicada)                                                  AS duplicadas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.franja <> 'LABORAL')                    AS fuera_horario
FROM v_alertas_tiempo t
CROSS JOIN g
GROUP BY g.granularidad, date_trunc(g.unidad, t.fecha_local);

-- ----------------------------------------------------------------------------
-- 6. CONTEXTO GEOPOLÍTICO: eventos externos para cruzar con los picos de alertas
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eventos_geopoliticos (
    evento_id    BIGSERIAL PRIMARY KEY,
    fecha_inicio DATE NOT NULL,
    fecha_fin    DATE,                     -- NULL = un solo día
    titulo       VARCHAR(200) NOT NULL,
    descripcion  TEXT,
    region       VARCHAR(100),
    actores      TEXT,                     -- p. ej. grupos APT o estados atribuidos
    fuente_url   TEXT,
    es_simulado  BOOLEAN NOT NULL DEFAULT FALSE,
    creado_por   VARCHAR(100) NOT NULL,
    fecha_alta   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_evento_fechas CHECK (fecha_fin IS NULL OR fecha_fin >= fecha_inicio)
);

-- Picos por hora: más del doble de la media de las 24 h anteriores (y al menos 3 alertas)
CREATE OR REPLACE VIEW v_picos_hora AS
WITH h AS (
    SELECT periodo AS hora, total, reales, criticas
    FROM v_stats_periodo WHERE granularidad = 'hora'
), m AS (
    SELECT h1.hora, h1.total, h1.reales, h1.criticas,
           (SELECT coalesce(sum(h2.total), 0) / 24.0 FROM h h2
            WHERE h2.hora >= h1.hora - interval '24 hours' AND h2.hora < h1.hora) AS media_24h
    FROM h h1
)
SELECT hora, total, reales, criticas, round(media_24h, 2) AS media_24h,
       total >= 3 AND total > 2 * media_24h AS es_pico
FROM m;

-- Día a día: alertas, media de los 7 días anteriores, pico y eventos geopolíticos activos ese día
CREATE OR REPLACE VIEW v_timeline_geopolitica AS
WITH d AS (
    SELECT periodo::date AS dia, total, reales, criticas
    FROM v_stats_periodo WHERE granularidad = 'dia'
), m AS (
    SELECT d1.*,
           (SELECT coalesce(sum(d2.total), 0) / 7.0 FROM d d2
            WHERE d2.dia >= d1.dia - 7 AND d2.dia < d1.dia) AS media_7d
    FROM d d1
)
SELECT m.dia, m.total, m.reales, m.criticas, round(m.media_7d, 2) AS media_7d,
       m.total >= 3 AND m.total > 2 * m.media_7d AS es_pico,
       count(e.evento_id) AS num_eventos,
       string_agg(e.titulo || CASE WHEN e.es_simulado THEN ' (simulado)' ELSE '' END, ' · '
                  ORDER BY e.fecha_inicio) AS eventos
FROM m
LEFT JOIN eventos_geopoliticos e
       ON m.dia BETWEEN e.fecha_inicio AND coalesce(e.fecha_fin, e.fecha_inicio)
GROUP BY m.dia, m.total, m.reales, m.criticas, m.media_7d;
