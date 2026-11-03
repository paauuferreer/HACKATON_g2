-- ============================================================================
-- 012_cadena_ransomware.sql — Fases del ataque y cadena de víctimas (investigación)
--
-- El buzón cuenta una intrusión que salta de cuenta en cuenta (jmoreno → amoreno → … → fmoreno,
-- equipos 201-207 en sedes distintas). Cada víctima recorre las mismas fases:
--   formulario falso → ráfaga de accesos fallidos → acceso no reconocido → lectura indebida →
--   mando y control → ejecución/persistencia → alteración de ficheros o pérdida de datos.
-- Esta migración asigna una fase a cada alerta por su título (tabla editable) y publica vistas para el
-- panel y la presentación. No bloquea nada. Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. FASES (inspiradas en la cadena de MITRE ATT&CK; patrón sobre el título plegado)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fases_ataque (
    fase        VARCHAR(30) PRIMARY KEY,
    orden       SMALLINT NOT NULL,
    nombre      VARCHAR(60) NOT NULL,
    patron      TEXT NOT NULL,            -- expresión regular sobre plegar(titulo)
    descripcion TEXT
);
INSERT INTO fases_ataque (fase, orden, nombre, patron, descripcion) VALUES
    ('RECONOCIMIENTO', 1, 'Reconocimiento',            'sondeo secuencial de puertos|peticion bloqueada con patron de explotacion',
     'Exploración del equipo antes o durante la intrusión'),
    ('ACCESO_INICIAL', 2, 'Phishing',                   'formulario falso de acceso',
     'Correo con formulario falso para robar la contraseña'),
    ('CREDENCIALES',   3, 'Fuerza bruta',               'rafaga de accesos fallidos',
     'Prueba masiva de contraseñas sobre la cuenta'),
    ('COMPROMISO',     4, 'Cuenta comprometida',        'acceso correcto que la persona titular no reconoce|uso confirmado de cuenta administrativa',
     'Inicio de sesión correcto que el titular no reconoce'),
    ('RECOLECCION',    5, 'Lectura indebida',           'lectura de documentos fuera de los permisos',
     'Acceso a documentos fuera de los permisos aprobados'),
    ('MANDO_CONTROL',  6, 'Mando y control',            'conexiones periodicas a infraestructura de mando',
     'Balizas periódicas hacia la infraestructura del atacante'),
    ('EJECUCION',      7, 'Ejecución / persistencia',   'aplicacion ejecuta proceso fuera de su funcion|proceso malicioso detectado|persistencia dirigida',
     'Procesos maliciosos y persistencia en el equipo'),
    ('IMPACTO',        8, 'Impacto (cifrado / pérdida)', 'alteracion no autorizada de ficheros|datos perdidos tras averia',
     'Ficheros alterados o datos perdidos: fase de ransomware')
ON CONFLICT (fase) DO NOTHING;

CREATE OR REPLACE FUNCTION fase_de_titulo(p_titulo TEXT) RETURNS VARCHAR AS $$
    SELECT f.fase FROM fases_ataque f
    WHERE plegar(split_part(coalesce(p_titulo, ''), ' · ', 1)) ~ f.patron
    ORDER BY f.orden
    LIMIT 1;
$$ LANGUAGE sql STABLE;

-- ----------------------------------------------------------------------------
-- 2. UNA FILA POR ALERTA CON FASE (las de equipo sin usuario se asignan a la víctima de ese equipo)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_fases_alertas AS
WITH base AS (
    SELECT a.alerta_id, lower(btrim(a.usuario_implicado)) AS usuario, a.equipo_afectado AS equipo, a.sede,
           coalesce(host(a.ip_afectada), a.ip_raw) AS ip, a.titulo, a.soc_prioridad, a.soc_peligrosidad,
           a.id_alerta_soc, a.estado,
           coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AS fecha_evento,
           a.fecha_hora_correo AS fecha_aviso,
           fase_de_titulo(a.titulo) AS fase
    FROM alertas a
    WHERE NOT a.es_duplicada AND a.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')
),
usuario_equipo AS (   -- usuario más frecuente de cada equipo
    SELECT DISTINCT ON (equipo) equipo, usuario
    FROM base WHERE usuario LIKE '%@%' AND equipo IS NOT NULL
    GROUP BY equipo, usuario
    ORDER BY equipo, count(*) DESC, usuario
)
SELECT b.alerta_id, coalesce(nullif(b.usuario, ''), ue.usuario) AS victima, (b.usuario IS NULL OR b.usuario = '') AS usuario_inferido,
       b.equipo, b.sede, b.ip, b.fase, f.orden AS orden_fase, f.nombre AS nombre_fase,
       b.titulo, b.soc_prioridad, b.soc_peligrosidad, b.id_alerta_soc, b.estado,
       b.fecha_evento, b.fecha_aviso
FROM base b
JOIN fases_ataque f ON f.fase = b.fase
LEFT JOIN usuario_equipo ue ON ue.equipo = b.equipo;

-- ----------------------------------------------------------------------------
-- 3. CADENA: víctimas con al menos 3 fases distintas, en orden de aparición
--    Horas en Europe/Madrid. "aviso" = cuando llegó el correo (cuando el sistema pudo actuar).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_cadena_victimas AS
WITH v AS (
    SELECT victima,
           min(fecha_evento)                                          AS inicio_evento,
           min(fecha_aviso)                                           AS inicio_aviso,
           max(fecha_evento)                                          AS fin_evento,
           count(DISTINCT fase)                                       AS num_fases,
           max(orden_fase)                                            AS fase_maxima_orden,
           string_agg(DISTINCT equipo, ', ')                          AS equipos,
           string_agg(DISTINCT sede, ', ')                            AS sedes,
           string_agg(DISTINCT ip, ', ')                              AS ips,
           min(fecha_aviso) FILTER (WHERE fase = 'COMPROMISO')        AS aviso_compromiso,
           min(fecha_aviso) FILTER (WHERE soc_peligrosidad = 'CRITICO') AS aviso_primera_critica,
           min(fecha_aviso) FILTER (WHERE fase = 'IMPACTO')           AS aviso_impacto
    FROM v_fases_alertas
    WHERE victima IS NOT NULL
    GROUP BY victima
    HAVING count(DISTINCT fase) >= 3
)
SELECT row_number() OVER (ORDER BY v.inicio_evento)                    AS orden_victima,
       v.victima, v.equipos, v.sedes, v.ips,
       v.inicio_evento AT TIME ZONE 'Europe/Madrid'                     AS inicio_evento_local,
       v.fin_evento AT TIME ZONE 'Europe/Madrid'                        AS fin_evento_local,
       round(extract(epoch FROM v.inicio_evento - lag(v.inicio_evento) OVER (ORDER BY v.inicio_evento)) / 60) AS min_desde_victima_anterior,
       v.inicio_aviso AT TIME ZONE 'Europe/Madrid'                      AS inicio_aviso_local,
       round(extract(epoch FROM v.inicio_aviso - lag(v.inicio_aviso) OVER (ORDER BY v.inicio_evento)) / 60) AS min_aviso_desde_victima_anterior,
       v.num_fases, f.nombre                                            AS fase_maxima,
       v.aviso_compromiso AT TIME ZONE 'Europe/Madrid'                  AS aviso_compromiso_local,
       v.aviso_primera_critica AT TIME ZONE 'Europe/Madrid'             AS aviso_primera_critica_local,
       round(extract(epoch FROM v.aviso_primera_critica - v.aviso_compromiso) / 60) AS min_ganados_detectando_compromiso,
       b.estado                                                         AS estado_bloqueo,
       b.origen                                                         AS origen_bloqueo,
       coalesce(b.confirmado, FALSE)                                    AS bloqueo_confirmado
FROM v
JOIN fases_ataque f ON f.orden = v.fase_maxima_orden
LEFT JOIN v_bloqueos_activos b ON b.tipo = 'USUARIO' AND b.valor = v.victima;

-- Detalle para la línea temporal: cada fase de cada víctima con el tiempo transcurrido
CREATE OR REPLACE VIEW v_cadena_ransomware AS
SELECT c.orden_victima, fa.victima, fa.usuario_inferido, fa.equipo, fa.sede, fa.ip,
       fa.orden_fase, fa.fase, fa.nombre_fase, fa.titulo, fa.soc_prioridad, fa.soc_peligrosidad, fa.id_alerta_soc,
       fa.fecha_evento AT TIME ZONE 'Europe/Madrid' AS evento_local,
       fa.fecha_aviso  AT TIME ZONE 'Europe/Madrid' AS aviso_local,
       round(extract(epoch FROM fa.fecha_evento - lag(fa.fecha_evento) OVER w) / 60) AS min_desde_fase_anterior,
       round(extract(epoch FROM fa.fecha_evento - first_value(fa.fecha_evento) OVER w) / 60) AS min_desde_inicio_victima,
       fa.alerta_id
FROM v_fases_alertas fa
JOIN v_cadena_victimas c ON c.victima = fa.victima
WINDOW w AS (PARTITION BY fa.victima ORDER BY fa.fecha_evento, fa.orden_fase);

-- Ritmo de propagación y hora estimada de la siguiente víctima (media de los saltos), en hora del evento
-- y en hora de aviso (llegada del correo, la que sirve para actuar en directo)
CREATE OR REPLACE VIEW v_cadena_prediccion AS
WITH u AS (
    SELECT orden_victima, victima, inicio_evento_local, min_desde_victima_anterior,
           inicio_aviso_local, min_aviso_desde_victima_anterior
    FROM v_cadena_victimas
)
SELECT count(*)                                                      AS victimas,
       round(avg(min_desde_victima_anterior))                        AS min_medios_entre_victimas,
       max(inicio_evento_local)                                      AS inicio_ultima_victima,
       (SELECT victima FROM u ORDER BY orden_victima DESC LIMIT 1)   AS ultima_victima,
       max(inicio_evento_local) + make_interval(mins => round(avg(min_desde_victima_anterior))::int)
                                                                     AS siguiente_victima_estimada_evento,
       round(avg(min_aviso_desde_victima_anterior))                  AS min_medios_entre_avisos,
       max(inicio_aviso_local) + make_interval(mins => round(avg(min_aviso_desde_victima_anterior))::int)
                                                                     AS siguiente_victima_estimada_aviso
FROM u;
