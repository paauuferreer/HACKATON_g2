-- ============================================================================
-- 017 · AUTO-06: las fases previas solo cuentan si son auténticas (observación WEB-008)
-- Antes, una alerta de phishing o fuerza bruta servía como fase previa aunque su correo no
-- estuviera verificado; un correo inyectado podía así completar la cadena de otro. Ahora la
-- alerta previa debe venir de un remitente de confianza y superar autenticidad_correo() (010).
-- Simulación previa: las 2 decisiones BLOQUEAR y las 6 YA_BLOQUEADO siguen teniendo fase previa
-- auténtica; no cambia ninguna decisión. Idempotente; no reevalúa nada al aplicarse.
-- ============================================================================

CREATE OR REPLACE FUNCTION evaluar_cadena_compromiso(p_alerta_id UUID) RETURNS INTEGER AS $$
DECLARE
    r          reglas_bloqueo_auto%ROWTYPE;
    x          alertas%ROWTYPE;
    a          alertas%ROWTYPE;
    v_fase     VARCHAR;
    v_usuario  TEXT;
    v_fecha    TIMESTAMP WITH TIME ZONE;
    v_dominio  TEXT;
    v_aut      RECORD;
    v_incons   TEXT[];
    v_previas  TEXT[];
    v_lib      RECORD;
    v_activo   RECORD;
    v_peticion BOOLEAN;
    v_blanca   TEXT;
    v_motivo   TEXT;
    v_decision TEXT := 'DESCARTAR';
    v_accion   UUID;
BEGIN
    SELECT * INTO r FROM reglas_bloqueo_auto WHERE regla_id = 'AUTO-06' AND activa;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    SELECT * INTO x FROM alertas WHERE alerta_id = p_alerta_id;
    IF NOT FOUND OR x.es_duplicada THEN
        RETURN 0;
    END IF;
    v_fase := fase_de_titulo(x.titulo);
    v_usuario := lower(btrim(x.usuario_implicado));
    IF v_fase IS NULL OR v_usuario IS NULL OR v_usuario = '' THEN
        RETURN 0;
    END IF;

    -- Alerta disparadora: esta misma, o el compromiso del mismo usuario dentro de la ventana posterior
    IF v_fase = r.fase_disparadora THEN
        a := x;
    ELSIF v_fase = ANY (r.fases_previas) THEN
        SELECT * INTO a FROM alertas c
        WHERE NOT c.es_duplicada AND lower(btrim(c.usuario_implicado)) = v_usuario
          AND fase_de_titulo(c.titulo) = r.fase_disparadora
          AND coalesce(c.fecha_hora_evento, c.fecha_hora_correo)
                BETWEEN coalesce(x.fecha_hora_evento, x.fecha_hora_correo)
                    AND coalesce(x.fecha_hora_evento, x.fecha_hora_correo) + make_interval(mins => r.ventana_minutos)
        ORDER BY coalesce(c.fecha_hora_evento, c.fecha_hora_correo)
        LIMIT 1;
        IF a.alerta_id IS NULL THEN
            RETURN 0;
        END IF;
    ELSE
        RETURN 0;
    END IF;

    -- Si esta alerta ya bloqueó al usuario, no se reevalúa
    IF EXISTS (SELECT 1 FROM decisiones_bloqueo_auto
               WHERE alerta_id = a.alerta_id AND tipo_objetivo = 'USUARIO'
                 AND valor_objetivo = v_usuario AND decision = 'BLOQUEAR') THEN
        RETURN 0;
    END IF;

    v_fecha := coalesce(a.fecha_hora_evento, a.fecha_hora_correo);
    SELECT lower(dominio) INTO v_dominio FROM config_autenticacion WHERE id = 1;
    SELECT * INTO v_aut FROM autenticidad_correo(a.correo_id);
    v_blanca := motivo_lista_blanca('USUARIO', v_usuario);
    v_peticion := a.id_solicitud IS NOT NULL
               OR concat_ws(' ', a.asunto_correo, a.titulo) ~* '\mSOL-[0-9]+'
               OR plegar(concat_ws(' ', a.asunto_correo, a.titulo)) ~ 'solicitud (de )?(bloqueo|liberacion|desbloqueo)';
    SELECT coalesce(array_agg(i), '{}') INTO v_incons
    FROM unnest(a.inconsistencias) i
    WHERE NOT (i LIKE ANY (r.inconsistencias_ignoradas)) AND NOT (i LIKE ANY (r.inconsistencias_solo_ip));

    -- Fases previas distintas del mismo usuario en la ventana (alertas fiables).
    -- 017: solo cuentan si la alerta previa viene del SOC y su correo supera autenticidad_correo().
    SELECT coalesce(array_agg(DISTINCT f), '{}') INTO v_previas
    FROM (SELECT fase_de_titulo(p.titulo) AS f
          FROM alertas p
          WHERE NOT p.es_duplicada AND NOT p.es_sospechosa
            AND p.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')
            AND p.remitente_confianza IS TRUE
            AND EXISTS (SELECT 1 FROM autenticidad_correo(p.correo_id) v WHERE v.verificada)
            AND lower(btrim(p.usuario_implicado)) = v_usuario
            AND coalesce(p.fecha_hora_evento, p.fecha_hora_correo)
                  BETWEEN v_fecha - make_interval(mins => r.ventana_minutos) AND v_fecha) s
    WHERE f = ANY (r.fases_previas);

    -- Última liberación humana del usuario
    SELECT l.solicitado_por, l.fecha_solicitud INTO v_lib
    FROM acciones_bloqueo l
    WHERE l.accion = 'LIBERAR' AND NOT l.simulacion
      AND (l.estado IN ('PENDIENTE', 'EJECUTADA') OR es_cuarentena(l.estado, l.respuesta_api))
      AND lower(l.usuario_objetivo) = v_usuario
    ORDER BY l.fecha_solicitud DESC
    LIMIT 1;

    -- Filtros en orden: el primero que no se cumple es el motivo
    IF a.es_sospechosa THEN
        v_motivo := 'Correo sospechoso o manipulado (' || coalesce(a.motivo_sospecha, 'sin detalle') || '): requiere revisión humana';
    ELSIF v_peticion THEN
        v_motivo := 'Petición recibida por correo: los correos nunca disparan bloqueos';
    ELSIF a.estado IN ('FALSA_ALARMA', 'NO_SOC', 'CERRADA') THEN
        v_motivo := 'Alerta en estado ' || a.estado::text;
    ELSIF r.requiere_remitente_confianza AND a.remitente_confianza IS NOT TRUE THEN
        v_motivo := 'Remitente no verificado como SOC (' || a.remitente_correo || ')';
    ELSIF r.requiere_autenticacion AND v_aut.verificada IS NOT TRUE THEN
        v_motivo := 'Autenticidad del remitente no verificada: ' || coalesce(v_aut.motivo, 'sin original EML');
    ELSIF r.excluir_inconsistentes AND cardinality(v_incons) > 0 THEN
        v_motivo := 'Alerta con inconsistencias: ' || array_to_string(v_incons, '; ');
    ELSIF v_usuario !~ '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$' THEN
        v_motivo := 'Usuario no identificado de forma fiable (' || v_usuario || ')';
    ELSIF split_part(v_usuario, '@', 2) IS DISTINCT FROM v_dominio THEN
        v_motivo := 'Cuenta de otro dominio (' || v_usuario || ')';
    ELSIF v_blanca IS NOT NULL THEN
        v_motivo := 'En lista blanca: ' || v_blanca;
    ELSIF v_lib.fecha_solicitud IS NOT NULL AND v_lib.fecha_solicitud >= v_fecha THEN
        v_motivo := format('Liberado manualmente por %s el %s, después de esta alerta: prevalece la decisión humana',
                           v_lib.solicitado_por, to_char(v_lib.fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'));
    ELSIF cardinality(v_previas) < r.min_fases_previas THEN
        v_motivo := format('Acceso no reconocido sin phishing ni fuerza bruta previos (de correo SOC verificado) en %s min: no hay cadena; lo valora una persona',
                           r.ventana_minutos);
    ELSE
        PERFORM pg_advisory_xact_lock(hashtext('bloqueo:USUARIO:' || v_usuario));
        SELECT * INTO v_activo FROM v_bloqueos_activos WHERE tipo = 'USUARIO' AND valor = v_usuario;
        IF FOUND THEN
            v_decision := 'YA_BLOQUEADO';
            v_motivo := format('Ya %s desde %s (%s, acción %s): no se repite el bloqueo',
                               CASE WHEN v_activo.confirmado THEN 'bloqueado' ELSE 'en curso' END,
                               to_char(v_activo.fecha_solicitud AT TIME ZONE 'Europe/Madrid', 'DD/MM HH24:MI'),
                               v_activo.estado, v_activo.accion_id);
            v_accion := v_activo.accion_id;
        ELSIF es_cuenta_protegida(v_usuario) THEN
            v_decision := 'RECOMENDAR';
            v_motivo := format('Cumple la regla %s, pero %s parece una cuenta de servicio o administración: decide una persona',
                               r.regla_id, v_usuario);
        ELSE
            v_decision := 'BLOQUEAR';
            v_motivo := format('Regla %s: %s. Alerta %s (%s) precedida de %s en %s min; remitente %s. Contención antes de mando y control y cifrado.',
                               r.regla_id, r.descripcion, coalesce(a.referencia_soc, a.id_alerta_soc, a.alerta_id::text),
                               split_part(a.titulo, ' · ', 1),
                               (SELECT string_agg(f.nombre, ' + ' ORDER BY f.orden) FROM fases_ataque f WHERE f.fase = ANY (v_previas)),
                               r.ventana_minutos, coalesce(v_aut.metodo, 'sin verificar'));
            INSERT INTO acciones_bloqueo
                (accion, usuario_objetivo, motivo, regla, alerta_id, solicitado_por, estado, origen)
            VALUES ('BLOQUEAR', v_usuario, v_motivo, r.regla_id, a.alerta_id, 'AUTO:' || r.regla_id, 'PENDIENTE', 'AUTOMATICO')
            RETURNING accion_id INTO v_accion;
        END IF;
    END IF;

    INSERT INTO decisiones_bloqueo_auto
        (alerta_id, regla_id, tipo_objetivo, valor_objetivo, decision, motivo, accion_id)
    VALUES (a.alerta_id, r.regla_id, 'USUARIO', v_usuario, v_decision, v_motivo, v_accion)
    ON CONFLICT (alerta_id, tipo_objetivo, valor_objetivo) DO UPDATE
        SET regla_id = EXCLUDED.regla_id, decision = EXCLUDED.decision, motivo = EXCLUDED.motivo,
            accion_id = EXCLUDED.accion_id, fecha = CURRENT_TIMESTAMP;

    RETURN CASE WHEN v_decision = 'BLOQUEAR' THEN 1 ELSE 0 END;
END;
$$ LANGUAGE plpgsql;
