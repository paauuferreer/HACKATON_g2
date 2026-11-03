-- ============================================================================
-- 010_bloqueo_critico_verificado.sql — Bloqueo automático de usuarios en casos claros (decisión D-007)
--
-- Contexto (BD-007, recuentos del 03/11/2026 sobre el original EML guardado):
--   * Los correos del SOC son internos al tenant: Exchange NO añade Authentication-Results (0 de 111),
--     ni llega x-ms-mail-application (0 de 111). Sí llegan, en todos los internos:
--     Received-SPF "Pass (protection.outlook.com: domain of sampol.com ...)", AuthAs Internal,
--     AuthMechanism y AuthSource. Con la 009 tal cual, ningún correo del SOC se verificaba.
--   * El director: la prioridad no es fiable (todas las críticas llegan [P4][CRÍTICO]); CRÍTICO manda.
--     "Automático en casos claros" y "empezar a bloquear usuarios ya", también las alertas ya recibidas.
--
-- Cambios:
--   1. autenticidad_correo(): si falta Authentication-Results y el correo es interno, se verifica con la
--      primera Received-SPF (pass de protection.outlook.com para el dominio) + AuthAs Internal +
--      AuthMechanism + AuthSource + un único From + SHA-256. Power Automate deja de exigirse por defecto.
--   2. Regla AUTO-05 "crítico verificado": CRÍTICO en el asunto con cualquier Px, cuerpo Crítica o Alta
--      (Media/Baja solo con 2 alertas críticas del mismo usuario en 2 h; si no, RECOMENDAR), clase de
--      compromiso, remitente SOC autenticado; incluye alertas antiguas. Una IP mal escrita invalida la IP,
--      no al usuario. AUTO-04 se desactiva.
--   3. Solo cuentas personales del dominio: las de servicio/administración pasan a RECOMENDAR.
-- No reevalúa nada al aplicarse: el histórico se encola con evaluar_bloqueo_pendientes() tras el OK humano.
-- Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CONFIGURACIÓN
-- ----------------------------------------------------------------------------
ALTER TABLE config_autenticacion ADD COLUMN IF NOT EXISTS aceptar_interno_sin_ar BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE config_autenticacion ADD COLUMN IF NOT EXISTS verificador_spf        VARCHAR(100) NOT NULL DEFAULT 'protection.outlook.com';
ALTER TABLE config_autenticacion ADD COLUMN IF NOT EXISTS exigir_power_automate  BOOLEAN NOT NULL DEFAULT FALSE;

-- Prefijos plegados de la criticidad del cuerpo que confirman la gravedad (NULL = no se mira)
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS criticidades_cuerpo TEXT[];
-- Cuerpos que solo valen con corroboración: N alertas críticas sobre el mismo usuario en la ventana;
-- sin ella, la decisión es RECOMENDAR
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS criticidades_corroboradas   TEXT[];
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS min_alertas_corroboracion   INTEGER NOT NULL DEFAULT 2;
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS ventana_corroboracion_min   INTEGER NOT NULL DEFAULT 120;
-- Inconsistencias que solo invalidan el objetivo IP (patrones LIKE), no al usuario
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS inconsistencias_solo_ip     TEXT[] NOT NULL DEFAULT '{}';

-- ----------------------------------------------------------------------------
-- 2. AUTENTICIDAD (sustituye a la de la 009; misma firma)
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
    v_spf      TEXT;
    v_authas   TEXT;
    v_mech     TEXT;
    v_source   TEXT;
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
    SELECT count(*) INTO v_num_from FROM cabeceras_eml(p_correo_id) h WHERE h.nombre = 'from';
    SELECT lower(btrim(coalesce(substring(valor FROM '<([^<>@\s]+@[^<>\s]+)>'), valor))) INTO v_from
    FROM cabeceras_eml(p_correo_id) h WHERE h.nombre = 'from' ORDER BY h.orden LIMIT 1;
    IF v_num_from <> 1 THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, format('El original tiene %s cabeceras From', v_num_from), TRUE; RETURN;
    ELSIF v_from IS DISTINCT FROM b.remitente THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, format('From del original (%s) distinto del remitente guardado (%s)', v_from, b.remitente), TRUE; RETURN;
    ELSIF split_part(v_from, '@', 2) <> lower(c.dominio) THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Remitente externo al dominio ' || c.dominio, TRUE; RETURN;
    END IF;

    -- Sellos de Exchange Online (los elimina de los correos externos)
    SELECT lower(btrim(valor)) INTO v_authas FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'x-ms-exchange-organization-authas' ORDER BY h.orden LIMIT 1;
    SELECT btrim(valor) INTO v_mech FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'x-ms-exchange-organization-authmechanism' ORDER BY h.orden LIMIT 1;
    SELECT btrim(valor) INTO v_source FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'x-ms-exchange-organization-authsource' ORDER BY h.orden LIMIT 1;

    v_dom_re := replace(lower(c.dominio), '.', '\.');
    SELECT lower(valor) INTO v_ar FROM cabeceras_eml(p_correo_id) h
    WHERE h.nombre = 'authentication-results' ORDER BY h.orden LIMIT 1;

    IF v_ar IS NOT NULL THEN
        -- Correo que entra desde fuera: SOLO la primera Authentication-Results, firmada por nuestro servidor
        IF split_part(btrim(split_part(v_ar, ';', 1)), ' ', 1) <> lower(c.authserv_id) THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Authentication-Results superior no es de ' || c.authserv_id, TRUE; RETURN;
        ELSIF v_ar !~ '\mdmarc=pass\M' OR v_ar !~ ('header\.from=' || v_dom_re || '(\s|;|$)') THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
                'DMARC no superado para ' || c.dominio || ' (' || coalesce(substring(v_ar FROM 'dmarc=[a-z]+'), 'sin dmarc') || ')', TRUE; RETURN;
        END IF;
        v_pruebas := array_append(v_pruebas, 'DMARC pass'::TEXT);
        IF v_ar ~ '\mspf=pass\M' THEN v_pruebas := array_append(v_pruebas, 'SPF pass'::TEXT); END IF;
        IF v_ar ~ '\mdkim=pass\M' THEN v_pruebas := array_append(v_pruebas, 'DKIM pass'::TEXT); END IF;
    ELSIF c.aceptar_interno_sin_ar THEN
        -- Correo interno del tenant: Exchange no añade Authentication-Results; vale la primera Received-SPF
        SELECT lower(valor) INTO v_spf FROM cabeceras_eml(p_correo_id) h
        WHERE h.nombre = 'received-spf' ORDER BY h.orden LIMIT 1;
        IF v_spf IS NULL THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Correo interno sin Authentication-Results ni Received-SPF', TRUE; RETURN;
        ELSIF v_spf !~ ('^pass \(' || replace(lower(c.verificador_spf), '.', '\.') || ':\s*domain of ' || v_dom_re || '\M') THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
                'Received-SPF superior no es un pass de ' || c.verificador_spf || ' para ' || c.dominio, TRUE; RETURN;
        ELSIF v_authas IS DISTINCT FROM 'internal' OR v_mech IS NULL OR v_source IS NULL THEN
            RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
                'Correo sin Authentication-Results y sin sellos internos de Exchange (AuthAs Internal, AuthMechanism, AuthSource)', TRUE; RETURN;
        END IF;
        v_pruebas := array_append(v_pruebas, 'Exchange interno: SPF pass'::TEXT);
    ELSE
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from, 'Falta Authentication-Results', TRUE; RETURN;
    END IF;

    -- Enviado desde dentro de Exchange Online con un buzón autenticado
    IF c.exigir_authas_internal AND v_authas IS DISTINCT FROM 'internal' THEN
        RETURN QUERY SELECT FALSE, NULL::TEXT, v_from,
            CASE WHEN v_authas IS NULL THEN 'Falta X-MS-Exchange-Organization-AuthAs en el original'
                 ELSE 'AuthAs = ' || v_authas || ' (se exige Internal)' END, TRUE; RETURN;
    END IF;
    IF v_authas = 'internal' THEN v_pruebas := array_append(v_pruebas, 'AuthAs Internal'::TEXT); END IF;

    -- Remitentes automatizados: solo si el equipo lo exige (el EML guardado no conserva x-ms-mail-application)
    IF c.exigir_power_automate AND v_from = ANY (SELECT lower(x) FROM unnest(c.remitentes_power_automate) x) THEN
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
-- 3. CUENTAS QUE NUNCA SE BLOQUEAN SOLAS (servicio, administración, buzones técnicos)
--    Mismo criterio que la política del ejecutor web; pasan a RECOMENDAR, decide una persona.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION es_cuenta_protegida(p_usuario TEXT) RETURNS BOOLEAN AS $$
    SELECT split_part(lower(p_usuario), '@', 1)
           ~ '(admin|root|system|service|servicio|svc|robot|bot|backup|sql|sync|monitor|breakglass|emergency|noreply|no-reply|support|soporte)';
$$ LANGUAGE sql IMMUTABLE;

-- ----------------------------------------------------------------------------
-- 4. REGLA AUTO-05 "crítico verificado"
-- ----------------------------------------------------------------------------
INSERT INTO reglas_bloqueo_auto
    (regla_id, descripcion, objetivo, prioridades, peligrosidades, clases_incibe,
     requiere_remitente_confianza, excluir_inconsistentes, solo_ip_publica, min_alertas, ventana_minutos, orden,
     antiguedad_max_minutos, exigir_criticidad_cuerpo, criticidades_cuerpo, criticidades_corroboradas,
     min_alertas_corroboracion, ventana_corroboracion_min, inconsistencias_ignoradas, inconsistencias_solo_ip,
     ip_automatica, requiere_autenticacion)
VALUES
    ('AUTO-05', 'Crítico verificado: asunto CRÍTICO (cualquier prioridad), cuerpo Crítica o Alta (Media o Baja solo con 2 alertas críticas del mismo usuario en 2 h), compromiso de una cuenta, remitente SOC autenticado',
     'AMBOS', '{P1,P2,P3,P4}', '{CRITICO}', '{INTRUSION,CONTENIDO_DANINO,COMPROMISO_INFORMACION}',
     TRUE, TRUE, TRUE, 1, 60, 5,
     NULL, FALSE, '{critic,alt}', '{medi,baj}',
     2, 120,
     '{"Prioridad % incoherente con gravedad %","Gravedad del asunto CRITICO distinta de la criticidad del cuerpo %"}',
     '{"Dirección relacionada con formato no válido%"}',
     FALSE, TRUE)
ON CONFLICT (regla_id) DO NOTHING;

-- AUTO-05 la sustituye (exigía cuerpo Crítica y una antigüedad máxima de 15 min)
UPDATE reglas_bloqueo_auto SET activa = FALSE, fecha_actualizacion = CURRENT_TIMESTAMP
WHERE regla_id = 'AUTO-04' AND activa;

-- ----------------------------------------------------------------------------
-- 5. EVALUACIÓN: igual que la 009 + criticidad del cuerpo con corroboración, inconsistencias por objetivo,
--    dominio y cuentas protegidas
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
    v_inc_obj  TEXT[];
    v_edad_min INTEGER;
    v_aut      RECORD;
    v_dominio  TEXT;
    v_cuerpo   TEXT;      -- CONFIRMA | CORROBORADA | SIN_CORROBORAR | NO
    v_corr     INTEGER;
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
    SELECT lower(dominio) INTO v_dominio FROM config_autenticacion WHERE id = 1;

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

    -- Autenticidad del remitente a partir del original EML (009/010)
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

        -- Una IP mal escrita invalida el objetivo IP, no al usuario
        v_inc_obj := CASE WHEN o.tipo = 'USUARIO'
                          THEN ARRAY(SELECT i FROM unnest(v_incons) i WHERE NOT (i LIKE ANY (r.inconsistencias_solo_ip)))
                          ELSE v_incons END;

        -- ¿Confirma el cuerpo la gravedad del asunto?
        v_corr := NULL;
        IF r.criticidades_cuerpo IS NULL
           OR coalesce(plegar(a.criticidad_cuerpo), '') LIKE ANY (SELECT x || '%' FROM unnest(r.criticidades_cuerpo) x) THEN
            v_cuerpo := 'CONFIRMA';
        ELSIF coalesce(plegar(a.criticidad_cuerpo), '') LIKE ANY (SELECT x || '%' FROM unnest(coalesce(r.criticidades_corroboradas, '{}')) x) THEN
            -- Alertas críticas únicas del mismo objetivo en la ventana, incluida esta
            SELECT count(*) INTO v_corr
            FROM alertas x
            WHERE NOT x.es_duplicada AND NOT x.es_sospechosa
              AND x.soc_peligrosidad = ANY (r.peligrosidades)
              AND x.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')
              AND coalesce(x.fecha_hora_evento, x.fecha_hora_correo)
                    BETWEEN v_fecha - make_interval(mins => r.ventana_corroboracion_min) AND v_fecha
              AND CASE o.tipo WHEN 'IP' THEN host(x.ip_afectada) = o.valor
                              ELSE lower(btrim(x.usuario_implicado)) = o.valor END;
            v_cuerpo := CASE WHEN v_corr >= r.min_alertas_corroboracion THEN 'CORROBORADA' ELSE 'SIN_CORROBORAR' END;
        ELSE
            v_cuerpo := 'NO';
        END IF;

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
        ELSIF v_cuerpo = 'NO' THEN
            v_motivo := format('El cuerpo no confirma la gravedad: el asunto dice %s y el cuerpo dice %s',
                               a.soc_peligrosidad, coalesce(a.criticidad_cuerpo, 'nada'));
        ELSIF r.excluir_inconsistentes AND cardinality(v_inc_obj) > 0 THEN
            v_motivo := 'Alerta con inconsistencias: ' || array_to_string(v_inc_obj, '; ');
        ELSIF o.tipo = 'USUARIO' AND o.valor !~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$' THEN
            v_motivo := 'Usuario no identificado de forma fiable (' || o.valor || '): se necesita una cuenta de correo completa';
        ELSIF o.tipo = 'USUARIO' AND split_part(o.valor, '@', 2) IS DISTINCT FROM v_dominio THEN
            v_motivo := 'Cuenta de otro dominio (' || o.valor || '): no es una cuenta de la empresa';
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
                ELSIF v_cuerpo = 'SIN_CORROBORAR' THEN
                    v_decision := 'RECOMENDAR';
                    v_motivo := format('Asunto %s pero cuerpo %s, y solo %s alerta(s) crítica(s) de %s en %s min (la regla %s exige %s): se recomienda bloquear, decide una persona',
                                       a.soc_peligrosidad, a.criticidad_cuerpo, v_corr, o.valor,
                                       r.ventana_corroboracion_min, r.regla_id, r.min_alertas_corroboracion);
                ELSIF o.tipo = 'USUARIO' AND es_cuenta_protegida(o.valor) THEN
                    v_decision := 'RECOMENDAR';
                    v_motivo := format('Cumple la regla %s, pero %s parece una cuenta de servicio o administración: se recomienda bloquear, decide una persona',
                                       r.regla_id, o.valor);
                ELSIF r.antiguedad_max_minutos IS NOT NULL AND v_edad_min > r.antiguedad_max_minutos THEN
                    v_decision := 'RECOMENDAR';
                    v_motivo := format('Cumple la regla %s, pero la alerta llegó hace %s min (máximo %s): se recomienda bloquear, decide una persona',
                                       r.regla_id, v_edad_min, r.antiguedad_max_minutos);
                ELSE
                    v_decision := 'BLOQUEAR';
                    v_motivo := format('Regla %s: %s. Alerta %s [%s][%s], cuerpo %s%s, clase %s; remitente %s; %s alerta(s) en %s min.%s',
                                       r.regla_id, r.descripcion, coalesce(a.referencia_soc, a.id_alerta_soc, a.alerta_id::text),
                                       a.soc_prioridad, a.soc_peligrosidad, coalesce(a.criticidad_cuerpo, '—'),
                                       CASE WHEN v_cuerpo = 'CORROBORADA'
                                            THEN format(' (corroborado por %s alertas críticas en %s min)', v_corr, r.ventana_corroboracion_min)
                                            ELSE '' END,
                                       coalesce(a.incibe_clase_id, '—'), coalesce(v_aut.metodo, 'sin verificar'),
                                       v_num, r.ventana_minutos,
                                       CASE WHEN cardinality(v_incons) > cardinality(v_inc_obj)
                                            THEN ' Nota: ' || array_to_string(ARRAY(SELECT unnest(v_incons) EXCEPT SELECT unnest(v_inc_obj)), '; ') || ' (solo afecta a la IP).'
                                            ELSE '' END);
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
