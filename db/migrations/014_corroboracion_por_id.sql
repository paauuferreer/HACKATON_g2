-- ============================================================================
-- 014_corroboracion_por_id.sql — La corroboración cuenta alertas distintas, no filas (corrige la 010)
--
-- Fallo: un "Reenvío de alerta ya notificada" que llega en el mismo lote que su original se evalúa
-- antes de que procesar_correo() lo marque como duplicado (el intercambio de original ocurre después
-- del INSERT). La misma alerta contaba dos veces: slopez@ (AL-20261030-0219, cuerpo Baja) pasó a
-- BLOQUEAR con "2 alertas críticas" cuando solo había una. Ahora se cuentan IDs del SOC distintos
-- (id_alerta_soc, o la propia alerta si no lo tiene). Mismo cambio en el recuento de min_alertas.
-- Corrige la decisión de slopez@ y anula su acción pendiente (OMITIDA, nunca se envió). Idempotente.
-- ============================================================================

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
            -- Alertas críticas distintas (por ID del SOC) del mismo objetivo en la ventana, incluida esta
            SELECT count(DISTINCT coalesce(x.id_alerta_soc, x.alerta_id::text)) INTO v_corr
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
            SELECT count(DISTINCT coalesce(x.id_alerta_soc, x.alerta_id::text)) INTO v_num
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

-- Corrección de la decisión errónea (solo si sigue sin enviarse)
UPDATE acciones_bloqueo
SET estado = 'OMITIDA', exito = FALSE, fecha_respuesta = now(),
    respuesta_api = jsonb_build_object('automation', jsonb_build_object(
        'phase', 'review_required', 'code', 'CORROBORACION_DUPLICADA',
        'detalle', 'Anulada por la migración 014 (aplicada antes como 013): el reenvío de la misma alerta contó como corroboración'))
WHERE estado = 'PENDIENTE' AND origen = 'AUTOMATICO' AND regla = 'AUTO-05'
  AND lower(usuario_objetivo) = 'slopez@sampol.com';

DELETE FROM decisiones_bloqueo_auto d
USING alertas a
WHERE d.alerta_id = a.alerta_id AND d.tipo_objetivo = 'USUARIO' AND d.valor_objetivo = 'slopez@sampol.com'
  AND d.decision = 'BLOQUEAR' AND a.id_alerta_soc = 'AL-20261030-0219'
  AND NOT EXISTS (SELECT 1 FROM acciones_bloqueo b WHERE b.accion_id = d.accion_id AND b.estado IN ('PENDIENTE', 'EN_CURSO', 'EJECUTADA'));

SELECT evaluar_bloqueo_auto(a.alerta_id)
FROM alertas a
WHERE a.id_alerta_soc = 'AL-20261030-0219' AND NOT a.es_duplicada;
