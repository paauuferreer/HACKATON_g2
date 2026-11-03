-- ============================================================================
-- 005_bloqueo_automatico.sql — Bloqueo automático de nivel 2 (decisión D-003)
--
-- Ante una alerta crítica muy clara, el sistema encola un BLOQUEO de la IP y/o del usuario.
-- La llamada real a la API la hace el ejecutor (soc/ejecutor_bloqueos.py), que registra la respuesta.
-- Reglas del equipo:
--   * Los correos NUNCA disparan bloqueos por petición (solicitudes SOL-...): solo alertas críticas.
--   * Varios filtros antes de bloquear; cada decisión (bloquear o descartar) queda justificada.
--   * Lista blanca de usuarios, IPs y rangos que nunca se bloquean automáticamente.
--   * Si el objetivo ya está bloqueado, no se vuelve a bloquear.
--   * Bloqueos permanentes hasta que una persona libere (liberación en un clic: solicitar_liberacion()).
-- Idempotente: se puede ejecutar varias veces.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ACCIONES DE BLOQUEO: estado de ejecución y origen
-- ----------------------------------------------------------------------------
ALTER TABLE acciones_bloqueo ADD COLUMN IF NOT EXISTS estado VARCHAR(12);
ALTER TABLE acciones_bloqueo ADD COLUMN IF NOT EXISTS origen VARCHAR(12);

-- Filas anteriores a esta migración: nunca deben quedar como pendientes de ejecutar
UPDATE acciones_bloqueo
SET estado = CASE WHEN exito THEN 'EJECUTADA' WHEN http_status IS NOT NULL THEN 'ERROR' ELSE 'OMITIDA' END
WHERE estado IS NULL;
UPDATE acciones_bloqueo SET origen = 'MANUAL' WHERE origen IS NULL;

ALTER TABLE acciones_bloqueo ALTER COLUMN estado SET DEFAULT 'PENDIENTE';
ALTER TABLE acciones_bloqueo ALTER COLUMN estado SET NOT NULL;
ALTER TABLE acciones_bloqueo ALTER COLUMN origen SET DEFAULT 'MANUAL';
ALTER TABLE acciones_bloqueo ALTER COLUMN origen SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_accion_estado') THEN
        ALTER TABLE acciones_bloqueo ADD CONSTRAINT chk_accion_estado
            CHECK (estado IN ('PENDIENTE', 'EJECUTADA', 'ERROR', 'OMITIDA'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_accion_origen') THEN
        ALTER TABLE acciones_bloqueo ADD CONSTRAINT chk_accion_origen
            CHECK (origen IN ('AUTOMATICO', 'MANUAL'));
    END IF;
    -- La API acepta un único objetivo por llamada: una fila = una IP o un usuario.
    -- NOT VALID: se exige a las filas nuevas sin revalidar las antiguas.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_un_objetivo') THEN
        ALTER TABLE acciones_bloqueo ADD CONSTRAINT chk_un_objetivo
            CHECK (num_nonnulls(usuario_objetivo, ip_objetivo) = 1) NOT VALID;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_acciones_pendientes ON acciones_bloqueo (fecha_solicitud) WHERE estado = 'PENDIENTE';
CREATE INDEX IF NOT EXISTS idx_acciones_ip      ON acciones_bloqueo (ip_objetivo);
CREATE INDEX IF NOT EXISTS idx_acciones_usuario ON acciones_bloqueo (lower(usuario_objetivo));

-- ----------------------------------------------------------------------------
-- 2. LISTA BLANCA: nunca se bloquean automáticamente (sí se puede bloquear a mano)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lista_blanca (
    lista_blanca_id BIGSERIAL PRIMARY KEY,
    tipo            VARCHAR(10) NOT NULL CHECK (tipo IN ('USUARIO', 'IP')),
    usuario         VARCHAR(255),          -- se compara sin distinguir mayúsculas
    red             CIDR,                  -- una IP (/32) o un rango completo
    motivo          TEXT NOT NULL,
    creado_por      VARCHAR(100) NOT NULL,
    activo          BOOLEAN NOT NULL DEFAULT TRUE,
    fecha_alta      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_lista_blanca_tipo CHECK (
        (tipo = 'USUARIO' AND usuario IS NOT NULL AND red IS NULL) OR
        (tipo = 'IP'      AND red IS NOT NULL     AND usuario IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lista_blanca_usuario ON lista_blanca (lower(usuario)) WHERE tipo = 'USUARIO';
CREATE UNIQUE INDEX IF NOT EXISTS uq_lista_blanca_red     ON lista_blanca (red)            WHERE tipo = 'IP';

-- ----------------------------------------------------------------------------
-- 3. REGLAS DE BLOQUEO AUTOMÁTICO (filtros configurables)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reglas_bloqueo_auto (
    regla_id                     VARCHAR(30) PRIMARY KEY,
    descripcion                  TEXT NOT NULL,
    activa                       BOOLEAN NOT NULL DEFAULT TRUE,
    objetivo                     VARCHAR(10) NOT NULL DEFAULT 'AMBOS' CHECK (objetivo IN ('IP', 'USUARIO', 'AMBOS')),
    prioridades                  prioridad_soc_enum[]    NOT NULL DEFAULT '{P1}',
    peligrosidades               peligrosidad_soc_enum[] NOT NULL DEFAULT '{CRITICO}',
    clases_incibe                VARCHAR(50)[],              -- NULL = cualquier clase
    requiere_remitente_confianza BOOLEAN NOT NULL DEFAULT TRUE,
    excluir_inconsistentes       BOOLEAN NOT NULL DEFAULT TRUE,
    solo_ip_publica              BOOLEAN NOT NULL DEFAULT TRUE,  -- las IPs internas pasan a revisión humana
    min_alertas                  INTEGER NOT NULL DEFAULT 1 CHECK (min_alertas >= 1),
    ventana_minutos              INTEGER NOT NULL DEFAULT 60 CHECK (ventana_minutos > 0),
    orden                        SMALLINT NOT NULL DEFAULT 100,
    fecha_actualizacion          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reglas iniciales. ON CONFLICT DO NOTHING: si el equipo las ajusta, la migración no las pisa.
INSERT INTO reglas_bloqueo_auto
    (regla_id, descripcion, objetivo, prioridades, peligrosidades, clases_incibe, min_alertas, ventana_minutos, orden)
VALUES
    ('AUTO-01', 'Acceso crítico a un servidor o cuenta comprometida (intrusión) confirmado por el SOC',
     'AMBOS', '{P1}', '{CRITICO}', '{INTRUSION}', 1, 60, 10),
    ('AUTO-02', 'Intento de intrusión crítico repetido desde el mismo origen (al menos 2 alertas en 30 min)',
     'IP', '{P1,P2}', '{CRITICO}', '{INTENTO_INTRUSION}', 2, 30, 20),
    ('AUTO-03', 'Malware crítico o compromiso de información con cuenta implicada',
     'USUARIO', '{P1}', '{CRITICO}', '{CONTENIDO_DANINO,COMPROMISO_INFORMACION}', 1, 60, 30)
ON CONFLICT (regla_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. DECISIONES: por qué se bloqueó o por qué NO (descartar también es una decisión)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS decisiones_bloqueo_auto (
    decision_id    BIGSERIAL PRIMARY KEY,
    alerta_id      UUID NOT NULL REFERENCES alertas(alerta_id) ON DELETE CASCADE,
    regla_id       VARCHAR(30) REFERENCES reglas_bloqueo_auto(regla_id),
    tipo_objetivo  VARCHAR(10) NOT NULL CHECK (tipo_objetivo IN ('IP', 'USUARIO')),
    valor_objetivo VARCHAR(255) NOT NULL,
    decision       VARCHAR(12) NOT NULL CHECK (decision IN ('BLOQUEAR', 'YA_BLOQUEADO', 'DESCARTAR')),
    motivo         TEXT NOT NULL,
    accion_id      UUID REFERENCES acciones_bloqueo(accion_id),
    fecha          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_decision UNIQUE (alerta_id, tipo_objetivo, valor_objetivo)
);
CREATE INDEX IF NOT EXISTS idx_decisiones_fecha ON decisiones_bloqueo_auto (fecha DESC);

-- ----------------------------------------------------------------------------
-- 5. FUNCIONES AUXILIARES
-- ----------------------------------------------------------------------------
-- IP privada, de loopback, enlace local o reservada (no se bloquea sin revisión humana)
CREATE OR REPLACE FUNCTION es_ip_no_publica(p_ip INET) RETURNS BOOLEAN AS $$
    SELECT p_ip << ANY (ARRAY[
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16',
        '100.64.0.0/10', '0.0.0.0/8', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10']::inet[])
        OR p_ip = ANY (ARRAY['0.0.0.0', '255.255.255.255']::inet[]);
$$ LANGUAGE sql IMMUTABLE;

-- Devuelve el motivo si el objetivo está en la lista blanca; NULL si no lo está
CREATE OR REPLACE FUNCTION motivo_lista_blanca(p_tipo TEXT, p_valor TEXT) RETURNS TEXT AS $$
    SELECT motivo FROM lista_blanca
    WHERE activo AND tipo = p_tipo
      AND ((p_tipo = 'USUARIO' AND lower(usuario) = lower(p_valor)) OR
           (p_tipo = 'IP' AND p_valor::inet <<= red))
    ORDER BY lista_blanca_id
    LIMIT 1;
$$ LANGUAGE sql STABLE;

-- ----------------------------------------------------------------------------
-- 6. ESTADO DE CADA OBJETIVO: la última acción válida manda
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_bloqueos_estado AS
SELECT DISTINCT ON (tipo, valor)
       tipo, valor, accion AS ultima_accion, estado, origen, motivo, regla, alerta_id, accion_id,
       solicitado_por, fecha_solicitud, fecha_respuesta, http_status
FROM (SELECT CASE WHEN ip_objetivo IS NOT NULL THEN 'IP' ELSE 'USUARIO' END AS tipo,
             coalesce(host(ip_objetivo), lower(usuario_objetivo))          AS valor,
             b.*
      FROM acciones_bloqueo b
      WHERE estado IN ('PENDIENTE', 'EJECUTADA') AND NOT simulacion
        AND num_nonnulls(usuario_objetivo, ip_objetivo) = 1) x
ORDER BY tipo, valor, fecha_solicitud DESC;

-- Lo que el dashboard muestra como "bloqueados ahora" (incluye los encolados aún sin respuesta)
CREATE OR REPLACE VIEW v_bloqueos_activos AS
SELECT tipo, valor, estado, origen, motivo, regla, alerta_id, accion_id, solicitado_por,
       fecha_solicitud, fecha_respuesta
FROM v_bloqueos_estado
WHERE ultima_accion = 'BLOQUEAR';

CREATE OR REPLACE VIEW v_decisiones_bloqueo AS
SELECT d.fecha, d.decision, d.tipo_objetivo, d.valor_objetivo, d.regla_id, d.motivo,
       d.alerta_id, a.titulo, a.soc_prioridad, a.soc_peligrosidad, a.incibe_clase_id,
       d.accion_id, b.estado AS estado_accion, b.http_status
FROM decisiones_bloqueo_auto d
JOIN alertas a ON a.alerta_id = d.alerta_id
LEFT JOIN acciones_bloqueo b ON b.accion_id = d.accion_id
ORDER BY d.fecha DESC;

-- ----------------------------------------------------------------------------
-- 7. EVALUACIÓN DE UNA ALERTA
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION evaluar_bloqueo_auto(p_alerta_id UUID) RETURNS INTEGER AS $$
DECLARE
    a          alertas%ROWTYPE;
    r          reglas_bloqueo_auto%ROWTYPE;
    o          RECORD;
    v_fecha    TIMESTAMP WITH TIME ZONE;
    v_motivo   TEXT;
    v_decision TEXT;
    v_blanca   TEXT;
    v_activo   RECORD;
    v_lib      RECORD;
    v_desde    TIMESTAMP WITH TIME ZONE;
    v_peticion BOOLEAN;
    v_num      INTEGER;
    v_accion   UUID;
    v_creadas  INTEGER := 0;
BEGIN
    SELECT * INTO a FROM alertas WHERE alerta_id = p_alerta_id;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    v_fecha := coalesce(a.fecha_hora_evento, a.fecha_hora_correo);
    -- Petición de bloqueo/liberación por correo, aunque el extractor no haya rellenado id_solicitud
    v_peticion := a.id_solicitud IS NOT NULL
               OR concat_ws(' ', a.asunto_correo, a.titulo) ~* '\mSOL-[0-9]+'
               OR plegar(concat_ws(' ', a.asunto_correo, a.titulo)) ~ 'solicitud (de )?(bloqueo|liberacion|desbloqueo)';

    -- Solo la primera regla activa que encaja (por orden) decide sobre la alerta
    SELECT * INTO r FROM reglas_bloqueo_auto
    WHERE activa
      AND a.soc_prioridad    = ANY (prioridades)
      AND a.soc_peligrosidad = ANY (peligrosidades)
      AND (clases_incibe IS NULL OR a.incibe_clase_id = ANY (clases_incibe))
    ORDER BY orden, regla_id
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN 0;   -- no es una situación "muy clara": ni se bloquea ni se registra decisión
    END IF;

    FOR o IN
        SELECT * FROM (VALUES ('IP',      host(a.ip_afectada)),
                              ('USUARIO', lower(a.usuario_implicado))) t(tipo, valor)
        WHERE t.valor IS NOT NULL AND (r.objetivo = 'AMBOS' OR r.objetivo = t.tipo)
    LOOP
        -- Si esta alerta ya bloqueó este objetivo, no se reevalúa
        IF EXISTS (SELECT 1 FROM decisiones_bloqueo_auto
                   WHERE alerta_id = a.alerta_id AND tipo_objetivo = o.tipo
                     AND valor_objetivo = o.valor AND decision = 'BLOQUEAR') THEN
            CONTINUE;
        END IF;

        v_motivo := NULL;
        v_decision := 'DESCARTAR';
        v_accion := NULL;
        v_blanca := motivo_lista_blanca(o.tipo, o.valor);

        -- Última liberación manual de este objetivo: la decisión humana prevalece sobre evidencias anteriores
        SELECT l.solicitado_por, l.fecha_solicitud INTO v_lib
        FROM acciones_bloqueo l
        WHERE l.accion = 'LIBERAR' AND l.estado IN ('PENDIENTE', 'EJECUTADA') AND NOT l.simulacion
          AND CASE o.tipo WHEN 'IP' THEN host(l.ip_objetivo) = o.valor
                          ELSE lower(l.usuario_objetivo) = o.valor END
        ORDER BY l.fecha_solicitud DESC
        LIMIT 1;
        v_desde := v_fecha - make_interval(mins => r.ventana_minutos);
        IF v_lib.fecha_solicitud IS NOT NULL AND v_lib.fecha_solicitud > v_desde THEN
            v_desde := v_lib.fecha_solicitud;   -- solo cuentan alertas posteriores a la liberación
        END IF;

        -- Filtros en orden: el primero que no se cumple es el motivo del descarte
        IF a.es_duplicada THEN
            v_motivo := 'Alerta duplicada: la decisión corresponde a la alerta original';
        ELSIF a.es_sospechosa THEN
            v_motivo := 'Correo sospechoso o manipulado (' || coalesce(a.motivo_sospecha, 'sin detalle') || '): requiere revisión humana';
        ELSIF v_peticion THEN
            v_motivo := 'Petición recibida por correo (' || coalesce(a.id_solicitud, 'solicitud') || '): los correos nunca disparan bloqueos';
        ELSIF a.estado IN ('FALSA_ALARMA', 'NO_SOC', 'CERRADA') THEN
            v_motivo := 'Alerta en estado ' || a.estado::text;
        ELSIF r.requiere_remitente_confianza AND a.remitente_confianza IS NOT TRUE THEN
            v_motivo := 'Remitente no verificado como SOC (' || a.remitente_correo || ')';
        ELSIF r.excluir_inconsistentes AND cardinality(a.inconsistencias) > 0 THEN
            v_motivo := 'Alerta con inconsistencias: ' || array_to_string(a.inconsistencias, '; ');
        ELSIF o.tipo = 'IP' AND r.solo_ip_publica AND es_ip_no_publica(o.valor::inet) THEN
            v_motivo := 'IP interna o reservada (' || o.valor || '): puede ser el servidor afectado; requiere revisión humana';
        ELSIF v_blanca IS NOT NULL THEN
            v_motivo := 'En lista blanca: ' || v_blanca;
        ELSIF v_lib.fecha_solicitud IS NOT NULL AND v_lib.fecha_solicitud >= v_fecha THEN
            v_motivo := format('Liberado manualmente por %s el %s, después de esta alerta: prevalece la decisión humana',
                               v_lib.solicitado_por,
                               to_char(v_lib.fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'));
        ELSE
            -- Corroboración: alertas únicas sobre el mismo objetivo dentro de la ventana
            SELECT count(*) INTO v_num
            FROM alertas x
            WHERE NOT x.es_duplicada AND NOT x.es_sospechosa
              AND x.soc_peligrosidad = ANY (r.peligrosidades)
              AND x.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')
              AND coalesce(x.fecha_hora_evento, x.fecha_hora_correo)
                    BETWEEN v_desde AND v_fecha
              AND CASE o.tipo WHEN 'IP' THEN host(x.ip_afectada) = o.valor
                              ELSE lower(x.usuario_implicado) = o.valor END;

            IF v_num < r.min_alertas THEN
                v_motivo := format('Solo %s alerta(s) en %s min; la regla %s exige %s',
                                   v_num, r.ventana_minutos, r.regla_id, r.min_alertas);
            ELSE
                -- Serializa decisiones concurrentes sobre el mismo objetivo
                PERFORM pg_advisory_xact_lock(hashtext('bloqueo:' || o.tipo || ':' || o.valor));

                SELECT * INTO v_activo FROM v_bloqueos_activos WHERE tipo = o.tipo AND valor = o.valor;
                IF FOUND THEN
                    v_decision := 'YA_BLOQUEADO';
                    v_motivo := format('Ya bloqueado desde %s (%s, acción %s): no se repite el bloqueo',
                                       to_char(v_activo.fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'),
                                       v_activo.estado, v_activo.accion_id);
                    v_accion := v_activo.accion_id;
                ELSE
                    v_decision := 'BLOQUEAR';
                    v_motivo := format('Regla %s: %s. Alerta %s [%s][%s], clase %s; %s alerta(s) en %s min.',
                                       r.regla_id, r.descripcion, coalesce(a.referencia_soc, a.alerta_id::text),
                                       a.soc_prioridad, a.soc_peligrosidad, coalesce(a.incibe_clase_id, '—'),
                                       v_num, r.ventana_minutos);
                    INSERT INTO acciones_bloqueo
                        (accion, usuario_objetivo, ip_objetivo, motivo, regla, alerta_id,
                         solicitado_por, estado, origen)
                    VALUES ('BLOQUEAR',
                            CASE WHEN o.tipo = 'USUARIO' THEN a.usuario_implicado END,
                            CASE WHEN o.tipo = 'IP' THEN o.valor::inet END,
                            v_motivo, r.regla_id, a.alerta_id,
                            'AUTO:' || r.regla_id, 'PENDIENTE', 'AUTOMATICO')
                    RETURNING accion_id INTO v_accion;
                    v_creadas := v_creadas + 1;
                END IF;
            END IF;
        END IF;

        INSERT INTO decisiones_bloqueo_auto
            (alerta_id, regla_id, tipo_objetivo, valor_objetivo, decision, motivo, accion_id)
        VALUES (a.alerta_id, r.regla_id, o.tipo, o.valor, v_decision, v_motivo, v_accion)
        ON CONFLICT (alerta_id, tipo_objetivo, valor_objetivo) DO UPDATE
            SET regla_id = EXCLUDED.regla_id, decision = EXCLUDED.decision, motivo = EXCLUDED.motivo,
                accion_id = EXCLUDED.accion_id, fecha = CURRENT_TIMESTAMP;
    END LOOP;

    RETURN v_creadas;
END;
$$ LANGUAGE plpgsql;

-- Reevalúa alertas críticas recientes que aún no han producido un bloqueo
-- (útil tras cambiar reglas o la lista blanca, o tras reaplicar_reglas()). Devuelve acciones creadas.
CREATE OR REPLACE FUNCTION evaluar_bloqueo_pendientes(p_horas INTEGER DEFAULT 24) RETURNS INTEGER AS $$
DECLARE
    v_id    UUID;
    v_total INTEGER := 0;
BEGIN
    FOR v_id IN
        SELECT a.alerta_id FROM alertas a
        WHERE NOT a.es_duplicada
          AND a.soc_peligrosidad = 'CRITICO'
          AND coalesce(a.fecha_hora_evento, a.fecha_hora_correo) >= now() - make_interval(hours => p_horas)
        ORDER BY coalesce(a.fecha_hora_evento, a.fecha_hora_correo)
    LOOP
        v_total := v_total + evaluar_bloqueo_auto(v_id);
    END LOOP;
    RETURN v_total;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 8. TRIGGER: evaluación inmediata al crear la alerta
--    Nunca rompe la ingesta: si la evaluación falla, la alerta se guarda igualmente
--    (procesar_correo() envía el correo a malformados si el INSERT de la alerta falla).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_bloqueo_auto() RETURNS TRIGGER AS $$
BEGIN
    BEGIN
        PERFORM evaluar_bloqueo_auto(NEW.alerta_id);
    EXCEPTION WHEN others THEN
        RAISE WARNING 'Bloqueo automático no evaluado para la alerta %: %', NEW.alerta_id, SQLERRM;
    END;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_bloqueo_auto ON alertas;
CREATE TRIGGER trigger_bloqueo_auto
    AFTER INSERT ON alertas
    FOR EACH ROW
    WHEN (NEW.soc_peligrosidad = 'CRITICO' AND NOT NEW.es_duplicada)
    EXECUTE FUNCTION trg_bloqueo_auto();

-- ----------------------------------------------------------------------------
-- 9. LIBERACIÓN RÁPIDA (un clic desde el dashboard). Devuelve la acción encolada.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION solicitar_liberacion(p_tipo TEXT, p_valor TEXT, p_usuario TEXT, p_motivo TEXT)
RETURNS UUID AS $$
DECLARE
    v_activo RECORD;
    v_accion UUID;
BEGIN
    IF p_tipo NOT IN ('IP', 'USUARIO') THEN
        RAISE EXCEPTION 'Tipo no válido: %', p_tipo;
    END IF;
    IF coalesce(btrim(p_usuario), '') = '' OR coalesce(btrim(p_motivo), '') = '' THEN
        RAISE EXCEPTION 'La liberación requiere responsable y motivo';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('bloqueo:' || p_tipo || ':' ||
                                  CASE WHEN p_tipo = 'IP' THEN host(p_valor::inet) ELSE lower(p_valor) END));
    SELECT * INTO v_activo FROM v_bloqueos_activos
    WHERE tipo = p_tipo
      AND valor = CASE WHEN p_tipo = 'IP' THEN host(p_valor::inet) ELSE lower(p_valor) END;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'No hay un bloqueo activo para % %', p_tipo, p_valor;
    END IF;

    INSERT INTO acciones_bloqueo
        (accion, usuario_objetivo, ip_objetivo, motivo, regla, alerta_id, solicitado_por, estado, origen)
    VALUES ('LIBERAR',
            CASE WHEN p_tipo = 'USUARIO' THEN p_valor END,
            CASE WHEN p_tipo = 'IP' THEN p_valor::inet END,
            p_motivo, v_activo.regla, v_activo.alerta_id, p_usuario, 'PENDIENTE', 'MANUAL')
    RETURNING accion_id INTO v_accion;
    RETURN v_accion;
END;
$$ LANGUAGE plpgsql;
