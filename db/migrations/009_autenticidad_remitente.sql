-- ============================================================================
-- 009_autenticidad_remitente.sql — Verificación de autenticidad del remitente (decisión D-006)
--
-- Basada en las cabeceras reales del buzón (revisadas en Outlook el 03/11/2026):
--   * Correo real del SOC: Authentication-Results de mx.microsoft.com con spf=pass, dmarc=pass,
--     header.from=sampol.com; X-MS-Exchange-Organization-AuthAs: Internal; enviado por un flujo de
--     Power Automate (x-ms-mail-application: Microsoft Power Automate). DKIM = none (relay de CodeTwo).
--   * Correo interno de una persona (Amira): igual SPF/DMARC/AuthAs, pero sin Power Automate.
--   => SPF/DMARC solo prueban "dominio sampol.com". La identidad la dan From + AuthAs Internal (Exchange
--      no deja enviar como otro buzón sin permiso) y, para el SOC, el flujo de Power Automate.
--
-- Reglas anti-falsificación:
--   * Solo cuenta la PRIMERA cabecera Authentication-Results (la más alta = la que añade nuestro servidor).
--     Un atacante puede incluir otras más abajo; se ignoran. "Authentication-Results-Original" no cuenta.
--   * X-MS-Exchange-Organization-* las sella Exchange y las elimina de los correos externos.
--   * Se parte SOLO del original EML (eml_raw) con su SHA-256, nunca de texto del cuerpo
--     ni de la tabla remitentes_confianza.
-- Si no se puede comprobar algo, el resultado es FALSE con el motivo. Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CONFIGURACIÓN (una sola fila)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_autenticacion (
    id                        SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    dominio                   VARCHAR(100) NOT NULL,
    authserv_id               VARCHAR(100) NOT NULL,        -- quién firma Authentication-Results
    exigir_authas_internal    BOOLEAN NOT NULL DEFAULT TRUE,
    remitentes_power_automate TEXT[]  NOT NULL DEFAULT '{}', -- remitentes que SOLO envía un flujo de Power Automate
    fecha_actualizacion       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO config_autenticacion (id, dominio, authserv_id, exigir_authas_internal, remitentes_power_automate)
VALUES (1, 'sampol.com', 'mx.microsoft.com', TRUE, '{soc-hackaton@sampol.com}')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS requiere_autenticacion BOOLEAN NOT NULL DEFAULT TRUE;

-- ----------------------------------------------------------------------------
-- 2. CABECERAS DEL ORIGINAL EML, EN ORDEN (1 = la más alta)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cabeceras_eml(p_correo_id UUID)
RETURNS TABLE (orden INTEGER, nombre TEXT, valor TEXT) AS $$
DECLARE
    b        RECORD;
    v_texto  TEXT;
    v_bloque TEXT;
BEGIN
    SELECT eml_raw, cabeceras ->> 'eml_encoding' AS enc INTO b
    FROM bandeja_entrada WHERE correo_id = p_correo_id;
    IF b.eml_raw IS NULL THEN
        RETURN;
    END IF;
    BEGIN
        -- Las cabeceras son ASCII: LATIN1 nunca falla al convertir los bytes
        v_texto := CASE WHEN b.enc = 'base64' THEN convert_from(decode(b.eml_raw, 'base64'), 'LATIN1')
                        ELSE b.eml_raw END;
    EXCEPTION WHEN others THEN
        RETURN;
    END;
    v_bloque := coalesce(substring(v_texto FROM '^(.*?)\r?\n\r?\n'), v_texto);
    v_bloque := regexp_replace(v_bloque, '\r?\n[ \t]+', ' ', 'g');   -- desplegar líneas de continuación
    RETURN QUERY
        SELECT x.ord::INTEGER,
               lower(btrim(split_part(x.linea, ':', 1))),
               btrim(substr(x.linea, strpos(x.linea, ':') + 1))
        FROM regexp_split_to_table(v_bloque, '\r?\n') WITH ORDINALITY AS x(linea, ord)
        WHERE strpos(x.linea, ':') > 1 AND x.linea !~ '^[ \t]';
END;
$$ LANGUAGE plpgsql STABLE;

-- ----------------------------------------------------------------------------
-- 3. VERIFICACIÓN DE UN CORREO
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION autenticidad_correo(p_correo_id UUID)
RETURNS TABLE (verificada BOOLEAN, metodo TEXT, emisor TEXT, motivo TEXT, integridad_ok BOOLEAN) AS $$
DECLARE
    c          config_autenticacion%ROWTYPE;
    b          RECORD;
    v_bytes    BYTEA;
    v_integro  BOOLEAN := FALSE;
    v_from     TEXT;
    v_num_from INTEGER;
    v_ar       TEXT;
    v_authas   TEXT;
    v_app      TEXT;
    v_dom_re   TEXT;
    v_pruebas  TEXT[] := '{}';
BEGIN
    SELECT * INTO c FROM config_autenticacion WHERE id = 1;
    SELECT correo_id, lower(btrim(remitente_correo)) AS remitente, eml_raw,
           cabeceras ->> 'eml_encoding' AS enc, lower(cabeceras ->> 'eml_sha256') AS sha
    INTO b FROM bandeja_entrada WHERE correo_id = p_correo_id;

    IF b.correo_id IS NULL THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::TEXT, 'Sin correo en bandeja_entrada', FALSE; RETURN;
    ELSIF b.eml_raw IS NULL THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::TEXT, 'Sin original EML: no se puede verificar', FALSE; RETURN;
    ELSIF coalesce(b.enc, '') NOT IN ('utf8', 'base64') OR coalesce(b.sha, '') !~ '^[0-9a-f]{64}$' THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::TEXT, 'Sin eml_encoding o eml_sha256 válidos en cabeceras', FALSE; RETURN;
    END IF;

    -- Integridad: SHA-256 de los bytes originales
    BEGIN
        v_bytes := CASE WHEN b.enc = 'base64' THEN decode(b.eml_raw, 'base64') ELSE convert_to(b.eml_raw, 'UTF8') END;
        v_integro := encode(sha256(v_bytes), 'hex') = b.sha;
    EXCEPTION WHEN others THEN
        v_integro := FALSE;
    END;
    IF NOT v_integro THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::TEXT, 'El original no coincide con su SHA-256: posible alteración', FALSE; RETURN;
    END IF;

    -- From: exactamente uno y coincide con el remitente guardado
    SELECT count(*), min(lower(btrim(coalesce(substring(valor FROM '<([^<>@\s]+@[^<>\s]+)>'), valor))))
    INTO v_num_from FROM cabeceras_eml(p_correo_id) h WHERE h.nombre = 'from';
    SELECT lower(btrim(coalesce(substring(valor FROM '<([^<>@\s]+@[^<>\s]+)>'), valor))) INTO v_from
    FROM cabeceras_eml(p_correo_id) h WHERE h.nombre = 'from' ORDER BY h.orden LIMIT 1;
    IF v_num_from <> 1 THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, format('El original tiene %s cabeceras From', v_num_from), TRUE; RETURN;
    ELSIF v_from IS DISTINCT FROM b.remitente THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, format('From del original (%s) distinto del remitente guardado (%s)', v_from, b.remitente), TRUE; RETURN;
    ELSIF split_part(v_from, '@', 2) <> lower(c.dominio) THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Remitente externo al dominio ' || c.dominio, TRUE; RETURN;
    END IF;

    -- Authentication-Results: SOLO la primera (la más alta), y debe firmarla nuestro servidor
    SELECT lower(valor) INTO v_ar FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'authentication-results' ORDER BY h.orden LIMIT 1;
    v_dom_re := replace(lower(c.dominio), '.', '\.');
    IF v_ar IS NULL THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Falta Authentication-Results', TRUE; RETURN;
    ELSIF split_part(btrim(split_part(v_ar, ';', 1)), ' ', 1) <> lower(c.authserv_id) THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Authentication-Results superior no es de ' || c.authserv_id, TRUE; RETURN;
    ELSIF v_ar !~ '\mdmarc=pass\M' OR v_ar !~ ('header\.from=' || v_dom_re || '(\s|;|$)') THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
            'DMARC no superado para ' || c.dominio || ' (' || coalesce(substring(v_ar FROM 'dmarc=[a-z]+'), 'sin dmarc') || ')', TRUE; RETURN;
    END IF;
    v_pruebas := array_append(v_pruebas, 'DMARC pass'::TEXT);
    IF v_ar ~ '\mspf=pass\M' THEN v_pruebas := array_append(v_pruebas, 'SPF pass'::TEXT); END IF;
    IF v_ar ~ '\mdkim=pass\M' THEN v_pruebas := array_append(v_pruebas, 'DKIM pass'::TEXT); END IF;

    -- Enviado desde dentro de Exchange Online con un buzón autenticado
    SELECT lower(btrim(valor)) INTO v_authas FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'x-ms-exchange-organization-authas' ORDER BY h.orden LIMIT 1;
    IF c.exigir_authas_internal AND v_authas IS DISTINCT FROM 'internal' THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
            CASE WHEN v_authas IS NULL THEN 'Falta X-MS-Exchange-Organization-AuthAs en el original'
                 ELSE 'AuthAs = ' || v_authas || ' (se exige Internal)' END, TRUE; RETURN;
    END IF;
    IF v_authas = 'internal' THEN v_pruebas := array_append(v_pruebas, 'AuthAs Internal'::TEXT); END IF;

    -- Remitentes automatizados: deben llegar desde su flujo de Power Automate
    IF v_from = ANY (SELECT lower(x) FROM unnest(c.remitentes_power_automate) x) THEN
        SELECT valor INTO v_app FROM cabeceras_eml(p_correo_id) h
        WHERE h.nombre = 'x-ms-mail-application' ORDER BY h.orden LIMIT 1;
        IF v_app IS NULL OR v_app !~* '^Microsoft Power Automate' THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
                'El remitente ' || v_from || ' solo envía mediante Power Automate y este correo no viene de ahí', TRUE; RETURN;
        END IF;
        v_pruebas := array_append(v_pruebas, 'Power Automate'::TEXT);
    END IF;

    v_pruebas := array_append(v_pruebas, 'SHA-256'::TEXT);
    RETURN QUERY SELECT TRUE, array_to_string(v_pruebas, ' + '), v_from || ' (Exchange Online, ' || c.dominio || ')',
                        'Remitente verificado', TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

-- ----------------------------------------------------------------------------
-- 4. VISTAS
-- ----------------------------------------------------------------------------
-- Contrato del ejecutor web: mismas columnas que en la 008 y dos nuevas al final
CREATE OR REPLACE VIEW v_evidencias_automatizacion AS
SELECT b.correo_id, b.remitente_correo, b.cuerpo_correo_raw, b.eml_raw, b.cabeceras,
       coalesce(au.verificada, FALSE) AS autenticacion_verificada,
       au.metodo                      AS autenticacion_metodo,
       au.emisor                      AS autenticacion_emisor,
       au.motivo                      AS autenticacion_motivo,
       coalesce(au.integridad_ok, FALSE) AS integridad_ok
FROM bandeja_entrada b
LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE;

-- Para el dashboard y para comprobar las directrices del director
CREATE OR REPLACE VIEW v_autenticidad_correos AS
SELECT b.correo_id, b.fecha_hora_correo, b.remitente_correo, b.asunto_correo,
       coalesce(au.verificada, FALSE) AS verificada, au.metodo, au.emisor, au.motivo,
       coalesce(au.integridad_ok, FALSE) AS integridad_ok,
       EXISTS (SELECT 1 FROM remitentes_confianza r WHERE lower(r.email) = lower(b.remitente_correo)) AS remitente_lista_confianza
FROM bandeja_entrada b
LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE;

-- Resumen sin contenidos (para comprobar la verificación sin exponer correos)
CREATE OR REPLACE VIEW v_autenticidad_resumen AS
SELECT remitente_correo, verificada, motivo, count(*) AS correos
FROM v_autenticidad_correos
GROUP BY remitente_correo, verificada, motivo;

-- ----------------------------------------------------------------------------
-- 5. EVALUACIÓN DE BLOQUEO: igual que la 008 + filtro de autenticidad (requiere_autenticacion)
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
    v_aut      RECORD;
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

    -- Autenticidad del remitente a partir del original EML (009)
    SELECT * INTO v_aut FROM autenticidad_correo(a.correo_id);

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
        ELSIF r.requiere_autenticacion AND v_aut.verificada IS NOT TRUE THEN
            v_motivo := 'Autenticidad del remitente no verificada: ' || coalesce(v_aut.motivo, 'sin original EML');
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

-- Reevalúa con el filtro nuevo (por antigüedad, solo afecta a recomendaciones y descartes)
SELECT evaluar_bloqueo_pendientes(24 * 30);
