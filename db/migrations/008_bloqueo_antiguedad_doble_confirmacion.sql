-- ============================================================================
-- 008_bloqueo_antiguedad_doble_confirmacion.sql — Bloqueo automático alineado con el ejecutor seguro (D-005)
--
-- Responde a WEB-004 / M-002 (web) y a la revisión de la 005:
--   1. Antigüedad máxima (15 min por defecto, igual que el ejecutor): una alerta más vieja ya no
--      bloquea sola; si cumple todo lo demás queda como RECOMENDAR (decide una persona).
--      Regenerar alertas (007) o cargar el histórico nunca dispara bloqueos.
--   2. Las IPs nunca se bloquean automáticamente (pueden ser servidores públicos): RECOMENDAR.
--      Se puede cambiar por regla con ip_automatica = TRUE si el equipo lo decide.
--   3. Regla AUTO-04 de doble confirmación para el formato real [P4][CRÍTICO]: exige criticidad
--      crítica también en el cuerpo e ignora solo "Prioridad Px incoherente con gravedad ...".
--   4. El usuario debe ser una cuenta de correo bien formada (evita valores mal extraídos).
--   5. Cuarentena durable: estados EN_CURSO (intención registrada antes del POST) y DESCONOCIDO
--      (resultado dudoso). Funciones reservar_ / cerrar_ / reconciliar_accion_bloqueo().
--   6. motivo_lista_blanca() sin casteos a inet para usuarios.
--   7. v_bloqueos_activos indica si el bloqueo está confirmado por la API.
-- Se puede aplicar antes o después de la 007 (recomendado: después). Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. NUEVOS FILTROS EN LAS REGLAS
-- ----------------------------------------------------------------------------
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS antiguedad_max_minutos    INTEGER DEFAULT 15;
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS exigir_criticidad_cuerpo  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS inconsistencias_ignoradas TEXT[]  NOT NULL DEFAULT '{}';  -- patrones LIKE
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS ip_automatica             BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_antiguedad_max') THEN
        ALTER TABLE reglas_bloqueo_auto ADD CONSTRAINT chk_antiguedad_max
            CHECK (antiguedad_max_minutos IS NULL OR antiguedad_max_minutos > 0);
    END IF;
END $$;

INSERT INTO reglas_bloqueo_auto
    (regla_id, descripcion, objetivo, prioridades, peligrosidades, clases_incibe, min_alertas, ventana_minutos,
     orden, exigir_criticidad_cuerpo, inconsistencias_ignoradas)
VALUES
    ('AUTO-04', 'Doble confirmación: compromiso crítico en el asunto Y en el cuerpo, cualquier prioridad',
     'AMBOS', '{P1,P2,P3,P4}', '{CRITICO}', '{INTRUSION,CONTENIDO_DANINO,COMPROMISO_INFORMACION}', 1, 60,
     40, TRUE, '{"Prioridad % incoherente con gravedad %"}')
ON CONFLICT (regla_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. DECISIÓN RECOMENDAR Y ESTADOS DE CUARENTENA
-- ----------------------------------------------------------------------------
ALTER TABLE decisiones_bloqueo_auto DROP CONSTRAINT IF EXISTS decisiones_bloqueo_auto_decision_check;
ALTER TABLE decisiones_bloqueo_auto DROP CONSTRAINT IF EXISTS chk_decision_valor;
ALTER TABLE decisiones_bloqueo_auto ADD CONSTRAINT chk_decision_valor
    CHECK (decision IN ('BLOQUEAR', 'YA_BLOQUEADO', 'RECOMENDAR', 'DESCARTAR'));

ALTER TABLE acciones_bloqueo ADD COLUMN IF NOT EXISTS operacion_id UUID;                       -- token de la reserva
ALTER TABLE acciones_bloqueo ADD COLUMN IF NOT EXISTS fecha_envio  TIMESTAMP WITH TIME ZONE;   -- intención registrada
ALTER TABLE acciones_bloqueo DROP CONSTRAINT IF EXISTS chk_accion_estado;
ALTER TABLE acciones_bloqueo ADD CONSTRAINT chk_accion_estado
    CHECK (estado IN ('PENDIENTE', 'EN_CURSO', 'EJECUTADA', 'ERROR', 'DESCONOCIDO', 'OMITIDA'));
-- PENDIENTE  : encolada, aún no se ha intentado
-- EN_CURSO   : intención guardada y confirmada ANTES del POST
-- EJECUTADA  : la API respondió bien (y, si el ejecutor lo hace, verificada con GET)
-- ERROR      : la API respondió con fallo conocido: no se bloqueó nada
-- DESCONOCIDO: timeout, caída o respuesta dudosa: cuarentena, nunca se reintenta sola
-- OMITIDA    : no se envió (filtro del ejecutor, lista blanca, liberación posterior...)

-- ¿Está este objetivo en cuarentena? (incluye la convención temporal del ejecutor web:
-- ERROR + respuesta_api.automation.phase = outcome_unknown / acknowledged)
CREATE OR REPLACE FUNCTION es_cuarentena(p_estado TEXT, p_respuesta JSONB) RETURNS BOOLEAN AS $$
    SELECT p_estado IN ('EN_CURSO', 'DESCONOCIDO')
        OR (p_estado = 'ERROR' AND p_respuesta -> 'automation' ->> 'phase' IN ('outcome_unknown', 'acknowledged'));
$$ LANGUAGE sql IMMUTABLE;

-- ----------------------------------------------------------------------------
-- 3. LISTA BLANCA SIN CASTEOS PELIGROSOS (WEB-004 punto 6)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION motivo_lista_blanca(p_tipo TEXT, p_valor TEXT) RETURNS TEXT AS $$
DECLARE
    v_ip     INET;
    v_motivo TEXT;
BEGIN
    IF p_tipo = 'USUARIO' THEN
        SELECT motivo INTO v_motivo FROM lista_blanca
        WHERE activo AND tipo = 'USUARIO' AND lower(usuario) = lower(p_valor)
        ORDER BY lista_blanca_id LIMIT 1;
    ELSIF p_tipo = 'IP' THEN
        BEGIN
            v_ip := p_valor::inet;
        EXCEPTION WHEN others THEN
            RETURN NULL;   -- un valor que no es IP nunca coincide con una red
        END;
        SELECT motivo INTO v_motivo FROM lista_blanca
        WHERE activo AND tipo = 'IP' AND v_ip <<= red
        ORDER BY lista_blanca_id LIMIT 1;
    END IF;
    RETURN v_motivo;
END;
$$ LANGUAGE plpgsql STABLE;

-- ----------------------------------------------------------------------------
-- 4. ESTADO DE CADA OBJETIVO (las columnas nuevas van al final)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_bloqueos_estado AS
SELECT DISTINCT ON (tipo, valor)
       tipo, valor, accion AS ultima_accion, estado, origen, motivo, regla, alerta_id, accion_id,
       solicitado_por, fecha_solicitud, fecha_respuesta, http_status,
       respuesta_api -> 'automation' ->> 'phase' AS fase_automatizacion,
       es_cuarentena(estado, respuesta_api)        AS en_cuarentena
FROM (SELECT CASE WHEN ip_objetivo IS NOT NULL THEN 'IP' ELSE 'USUARIO' END AS tipo,
             coalesce(host(ip_objetivo), lower(usuario_objetivo))          AS valor,
             b.*
      FROM acciones_bloqueo b
      WHERE NOT simulacion
        AND num_nonnulls(usuario_objetivo, ip_objetivo) = 1
        AND (estado IN ('PENDIENTE', 'EJECUTADA') OR es_cuarentena(estado, respuesta_api))) x
ORDER BY tipo, valor, fecha_solicitud DESC;

-- ¿Hay un BLOQUEAR aceptado por la API sin ninguna liberación posterior?
CREATE OR REPLACE FUNCTION bloqueo_confirmado(p_tipo TEXT, p_valor TEXT) RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM acciones_bloqueo e
        WHERE e.accion = 'BLOQUEAR' AND e.estado = 'EJECUTADA' AND NOT e.simulacion
          AND CASE p_tipo WHEN 'IP' THEN host(e.ip_objetivo) = p_valor ELSE lower(e.usuario_objetivo) = p_valor END
          AND NOT EXISTS (
              SELECT 1 FROM acciones_bloqueo l
              WHERE l.accion = 'LIBERAR' AND NOT l.simulacion
                AND (l.estado IN ('PENDIENTE', 'EJECUTADA') OR es_cuarentena(l.estado, l.respuesta_api))
                AND l.fecha_solicitud > e.fecha_solicitud
                AND CASE p_tipo WHEN 'IP' THEN host(l.ip_objetivo) = p_valor ELSE lower(l.usuario_objetivo) = p_valor END));
$$ LANGUAGE sql STABLE;

-- Bloqueado o en vías de estarlo. "confirmado" = la API lo ha aceptado; PENDIENTE y cuarentena NO lo son.
CREATE OR REPLACE VIEW v_bloqueos_activos AS
SELECT tipo, valor, estado, origen, motivo, regla, alerta_id, accion_id, solicitado_por,
       fecha_solicitud, fecha_respuesta,
       bloqueo_confirmado(tipo, valor) AS confirmado,
       en_cuarentena, fase_automatizacion
FROM v_bloqueos_estado
WHERE ultima_accion = 'BLOQUEAR';

-- Operaciones que necesitan a una persona: fallos y resultados desconocidos
CREATE OR REPLACE VIEW v_bloqueos_revision AS
SELECT b.accion_id, b.accion, coalesce(host(b.ip_objetivo), b.usuario_objetivo) AS objetivo,
       b.estado, es_cuarentena(b.estado, b.respuesta_api) AS en_cuarentena,
       b.respuesta_api -> 'automation' ->> 'phase' AS fase_automatizacion,
       b.respuesta_api -> 'automation' ->> 'code'  AS codigo_ejecutor,
       b.http_status, b.regla, b.origen, b.solicitado_por, b.alerta_id,
       b.fecha_solicitud, b.fecha_envio, b.fecha_respuesta
FROM acciones_bloqueo b
WHERE NOT b.simulacion AND b.estado IN ('ERROR', 'DESCONOCIDO', 'EN_CURSO', 'OMITIDA')
ORDER BY b.fecha_solicitud DESC;

-- ----------------------------------------------------------------------------
-- 5. EVALUACIÓN (sustituye a la de la 005)
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
    v_incons   TEXT[];
    v_edad_min INTEGER;
    v_num      INTEGER;
    v_accion   UUID;
    v_creadas  INTEGER := 0;
BEGIN
    SELECT * INTO a FROM alertas WHERE alerta_id = p_alerta_id;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    v_fecha := coalesce(a.fecha_hora_evento, a.fecha_hora_correo);
    -- Antigüedad desde que llegó el correo (cuando el SOC nos avisó)
    v_edad_min := floor(extract(epoch FROM (now() - a.fecha_hora_correo)) / 60);
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

    -- Inconsistencias que cuentan para esta regla (sin las que la regla ignora expresamente)
    SELECT coalesce(array_agg(i), '{}') INTO v_incons
    FROM unnest(a.inconsistencias) i
    WHERE NOT (i LIKE ANY (r.inconsistencias_ignoradas));

    FOR o IN
        SELECT * FROM (VALUES ('IP',      host(a.ip_afectada)),
                              ('USUARIO', lower(btrim(a.usuario_implicado)))) t(tipo, valor)
        WHERE t.valor IS NOT NULL AND t.valor <> '' AND (r.objetivo = 'AMBOS' OR r.objetivo = t.tipo)
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
        WHERE l.accion = 'LIBERAR' AND NOT l.simulacion
          AND (l.estado IN ('PENDIENTE', 'EJECUTADA') OR es_cuarentena(l.estado, l.respuesta_api))
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
        ELSIF r.exigir_criticidad_cuerpo AND plegar(a.criticidad_cuerpo) NOT LIKE 'critic%' THEN
            v_motivo := format('Sin doble confirmación: el asunto dice %s pero el cuerpo dice %s',
                               a.soc_peligrosidad, coalesce(a.criticidad_cuerpo, 'nada'));
        ELSIF r.excluir_inconsistentes AND cardinality(v_incons) > 0 THEN
            v_motivo := 'Alerta con inconsistencias: ' || array_to_string(v_incons, '; ');
        ELSIF o.tipo = 'USUARIO' AND o.valor !~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$' THEN
            v_motivo := 'Usuario no identificado de forma fiable (' || o.valor || '): se necesita una cuenta de correo completa';
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
              AND coalesce(x.fecha_hora_evento, x.fecha_hora_correo) BETWEEN v_desde AND v_fecha
              AND CASE o.tipo WHEN 'IP' THEN host(x.ip_afectada) = o.valor
                              ELSE lower(btrim(x.usuario_implicado)) = o.valor END;

            IF v_num < r.min_alertas THEN
                v_motivo := format('Solo %s alerta(s) en %s min; la regla %s exige %s',
                                   v_num, r.ventana_minutos, r.regla_id, r.min_alertas);
            ELSE
                -- Serializa decisiones concurrentes sobre el mismo objetivo (misma clave que el ejecutor)
                PERFORM pg_advisory_xact_lock(hashtext('bloqueo:' || o.tipo || ':' || o.valor));

                SELECT * INTO v_activo FROM v_bloqueos_activos WHERE tipo = o.tipo AND valor = o.valor;
                IF FOUND THEN
                    v_decision := 'YA_BLOQUEADO';
                    v_motivo := format('Ya %s desde %s (%s, acción %s): no se repite el bloqueo',
                                       CASE WHEN v_activo.confirmado THEN 'bloqueado' ELSE 'en curso' END,
                                       to_char(v_activo.fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'),
                                       v_activo.estado, v_activo.accion_id);
                    v_accion := v_activo.accion_id;
                ELSIF o.tipo = 'IP' AND NOT r.ip_automatica THEN
                    v_decision := 'RECOMENDAR';
                    v_motivo := format('Cumple la regla %s, pero las IPs no se bloquean solas (podría ser un servidor público): se recomienda bloquear, decide una persona',
                                       r.regla_id);
                ELSIF r.antiguedad_max_minutos IS NOT NULL AND v_edad_min > r.antiguedad_max_minutos THEN
                    v_decision := 'RECOMENDAR';
                    v_motivo := format('Cumple la regla %s, pero la alerta llegó hace %s min (máximo %s): se recomienda bloquear, decide una persona',
                                       r.regla_id, v_edad_min, r.antiguedad_max_minutos);
                ELSE
                    v_decision := 'BLOQUEAR';
                    v_motivo := format('Regla %s: %s. Alerta %s [%s][%s], clase %s; %s alerta(s) en %s min.',
                                       r.regla_id, r.descripcion, coalesce(a.referencia_soc, a.id_alerta_soc, a.alerta_id::text),
                                       a.soc_prioridad, a.soc_peligrosidad, coalesce(a.incibe_clase_id, '—'),
                                       v_num, r.ventana_minutos);
                    INSERT INTO acciones_bloqueo
                        (accion, usuario_objetivo, ip_objetivo, motivo, regla, alerta_id,
                         solicitado_por, estado, origen)
                    VALUES ('BLOQUEAR',
                            CASE WHEN o.tipo = 'USUARIO' THEN o.valor END,
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

-- ----------------------------------------------------------------------------
-- 6. CONTRATO TRANSACCIONAL DEL EJECUTOR (M-002 web punto 6, WEB-004 puntos 3 y 4)
--    Uso: tx1 = SELECT reservar_accion_bloqueo(id) → COMMIT → POST a la API →
--         tx2 = SELECT cerrar_accion_bloqueo(id, token, 'EJECUTADA'|'ERROR'|'DESCONOCIDO', http, json) → COMMIT
--    Si el proceso cae entre tx1 y tx2, la fila queda EN_CURSO: cuarentena, nunca se repite el POST.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION reservar_accion_bloqueo(p_accion_id UUID) RETURNS UUID AS $$
DECLARE
    b       acciones_bloqueo%ROWTYPE;
    v_tipo  TEXT;
    v_valor TEXT;
    v_token UUID := gen_random_uuid();
BEGIN
    SELECT * INTO b FROM acciones_bloqueo WHERE accion_id = p_accion_id;
    IF NOT FOUND OR b.estado <> 'PENDIENTE' OR b.simulacion
       OR num_nonnulls(b.usuario_objetivo, b.ip_objetivo) <> 1 THEN
        RETURN NULL;
    END IF;
    v_tipo  := CASE WHEN b.ip_objetivo IS NOT NULL THEN 'IP' ELSE 'USUARIO' END;
    v_valor := coalesce(host(b.ip_objetivo), lower(b.usuario_objetivo));

    -- Misma clave que evaluar_bloqueo_auto(), solicitar_liberacion() y el ejecutor web
    PERFORM pg_advisory_xact_lock(hashtext('bloqueo:' || v_tipo || ':' || v_valor));
    SELECT * INTO b FROM acciones_bloqueo WHERE accion_id = p_accion_id FOR UPDATE;
    IF b.estado <> 'PENDIENTE' THEN
        RETURN NULL;
    END IF;

    -- Otra operación sobre el mismo objetivo sin resolver: no se envía nada
    IF EXISTS (SELECT 1 FROM acciones_bloqueo x
               WHERE x.accion_id <> b.accion_id AND NOT x.simulacion
                 AND es_cuarentena(x.estado, x.respuesta_api)
                 AND coalesce(host(x.ip_objetivo), lower(x.usuario_objetivo)) = v_valor) THEN
        RETURN NULL;
    END IF;

    IF b.accion = 'BLOQUEAR' THEN
        -- Ya bloqueado y confirmado por la API: no se repite el POST
        IF bloqueo_confirmado(v_tipo, v_valor) THEN
            UPDATE acciones_bloqueo
            SET estado = 'OMITIDA', exito = FALSE, fecha_respuesta = now(),
                respuesta_api = coalesce(respuesta_api, '{}'::jsonb)
                                || jsonb_build_object('omitida', 'El objetivo ya está bloqueado y confirmado')
            WHERE accion_id = b.accion_id;
            RETURN NULL;
        END IF;
        IF motivo_lista_blanca(v_tipo, v_valor) IS NOT NULL
           OR EXISTS (SELECT 1 FROM acciones_bloqueo l
                      WHERE l.accion = 'LIBERAR' AND NOT l.simulacion
                        AND l.estado IN ('PENDIENTE', 'EN_CURSO', 'EJECUTADA')
                        AND l.fecha_solicitud > b.fecha_solicitud
                        AND coalesce(host(l.ip_objetivo), lower(l.usuario_objetivo)) = v_valor) THEN
            UPDATE acciones_bloqueo
            SET estado = 'OMITIDA', exito = FALSE, fecha_respuesta = now(),
                respuesta_api = coalesce(respuesta_api, '{}'::jsonb)
                                || jsonb_build_object('omitida', 'Lista blanca o liberación humana posterior a la solicitud')
            WHERE accion_id = b.accion_id;
            RETURN NULL;
        END IF;
    END IF;

    UPDATE acciones_bloqueo
    SET estado = 'EN_CURSO', operacion_id = v_token, fecha_envio = now()
    WHERE accion_id = b.accion_id;
    RETURN v_token;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cerrar_accion_bloqueo(p_accion_id UUID, p_token UUID, p_resultado TEXT,
                                                 p_http INTEGER, p_respuesta JSONB)
RETURNS BOOLEAN AS $$
BEGIN
    IF p_resultado NOT IN ('EJECUTADA', 'ERROR', 'DESCONOCIDO') THEN
        RAISE EXCEPTION 'Resultado no válido: %', p_resultado;
    END IF;
    UPDATE acciones_bloqueo
    SET estado = p_resultado, exito = (p_resultado = 'EJECUTADA'), http_status = p_http,
        respuesta_api = p_respuesta, fecha_respuesta = now()
    WHERE accion_id = p_accion_id AND estado = 'EN_CURSO' AND operacion_id = p_token;
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Una persona resuelve una operación dudosa tras comprobar GET /equipo-2/bloqueos
CREATE OR REPLACE FUNCTION reconciliar_accion_bloqueo(p_accion_id UUID, p_resultado TEXT,
                                                      p_usuario TEXT, p_motivo TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    IF p_resultado NOT IN ('EJECUTADA', 'ERROR') THEN
        RAISE EXCEPTION 'Resultado no válido: %', p_resultado;
    END IF;
    IF coalesce(btrim(p_usuario), '') = '' OR coalesce(btrim(p_motivo), '') = '' THEN
        RAISE EXCEPTION 'La reconciliación requiere responsable y motivo';
    END IF;
    UPDATE acciones_bloqueo
    SET estado = p_resultado, exito = (p_resultado = 'EJECUTADA'), fecha_respuesta = now(),
        respuesta_api = coalesce(respuesta_api, '{}'::jsonb) || jsonb_build_object('reconciliacion',
            jsonb_build_object('por', p_usuario, 'motivo', p_motivo, 'fecha', now(), 'estado_previo', estado))
    WHERE accion_id = p_accion_id AND es_cuarentena(estado, respuesta_api);
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 7. RECOMENDACIONES PENDIENTES (botón "Bloquear" manual en el dashboard)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_recomendaciones_bloqueo AS
SELECT DISTINCT ON (d.tipo_objetivo, d.valor_objetivo)
       d.tipo_objetivo, d.valor_objetivo, d.regla_id, d.motivo, d.alerta_id,
       a.titulo, a.soc_prioridad, a.soc_peligrosidad, a.criticidad_cuerpo, a.incibe_clase_id,
       a.equipo_afectado, a.fecha_hora_correo, d.fecha AS fecha_decision,
       (SELECT count(*) FROM decisiones_bloqueo_auto d2
        WHERE d2.tipo_objetivo = d.tipo_objetivo AND d2.valor_objetivo = d.valor_objetivo
          AND d2.decision = 'RECOMENDAR') AS alertas_que_lo_recomiendan
FROM decisiones_bloqueo_auto d
JOIN alertas a ON a.alerta_id = d.alerta_id
WHERE d.decision = 'RECOMENDAR'
  AND NOT EXISTS (SELECT 1 FROM v_bloqueos_activos b
                  WHERE b.tipo = d.tipo_objetivo AND b.valor = d.valor_objetivo)
ORDER BY d.tipo_objetivo, d.valor_objetivo, a.fecha_hora_correo DESC;

-- ----------------------------------------------------------------------------
-- 8. EVIDENCIAS PARA EL EJECUTOR WEB (WEB-004 punto 2)
--    La autenticidad del remitente NO se deduce del From ni de remitentes_confianza.
--    Hasta verificarla con las cabeceras que añade el propio servidor de correo (siguiente migración,
--    tras revisar cabeceras reales), vale FALSE: el ejecutor se abstiene y pide revisión humana.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_evidencias_automatizacion AS
SELECT b.correo_id, b.remitente_correo, b.cuerpo_correo_raw, b.eml_raw, b.cabeceras,
       FALSE                AS autenticacion_verificada,
       NULL::TEXT           AS autenticacion_metodo,
       NULL::TEXT           AS autenticacion_emisor
FROM bandeja_entrada b;

-- Reevaluación de las alertas críticas del último mes con las reglas nuevas.
-- Por el filtro de antigüedad, solo genera recomendaciones: no encola bloqueos de alertas viejas.
SELECT evaluar_bloqueo_pendientes(24 * 30);
