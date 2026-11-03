-- ============================================================================
-- 003_formato_real_y_reglas.sql — Adaptación al formato real del buzón y clasificación por reglas
--
-- Formato observado (correos del SOC, 03/11):
--   Asunto: [SOC][Px][GRAVEDAD] Título · AL-AAAAMMDD-NNNN   (o SOL-B-NNN / SOL-L-NNN / nota NN)
--   Cuerpo: tabla "Cuenta relacionada | Recurso | Direccion relacionada | Sede | Criticidad |
--           Fuente | Regla de detección" + "ID de alerta:", "Primer evento:", "Último evento:", "Emisión:".
--   Trampas: P4 con CRÍTICO, criticidad del cuerpo distinta del asunto, IP mal formada,
--            reenvíos de una alerta ya notificada (mismo AL-...).
--
-- Cambios:
--   * Nuevos campos extraídos (sede, regla, IDs, fechas, inconsistencias).
--   * Duplicados por ID de alerta (AL-...) o de solicitud (SOL-...); si llega antes un
--     correo más antiguo, pasa a ser el original (importaciones históricas desordenadas).
--   * Clasificación INCIBE con reglas editables (tabla reglas_clasificacion) sobre el título.
--   * Lista de remitentes de confianza: el resto se marca como sospechoso.
--   * Gravedad del asunto admite femenino (ALTA, MEDIA, BAJA, CRÍTICA, INFORMATIVA).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. NUEVOS CAMPOS
-- ----------------------------------------------------------------------------
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS sede                VARCHAR(100);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS regla_deteccion     VARCHAR(100);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS criticidad_cuerpo   VARCHAR(30);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS ip_raw              VARCHAR(100);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS id_alerta_soc       VARCHAR(50);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS referencia_soc      VARCHAR(60);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS id_solicitud        VARCHAR(30);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS fecha_ultimo_evento TIMESTAMP WITH TIME ZONE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS fecha_emision       TIMESTAMP WITH TIME ZONE;
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS inconsistencias     TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS regla_id            VARCHAR(20);
ALTER TABLE alertas ADD COLUMN IF NOT EXISTS remitente_confianza BOOLEAN;

CREATE INDEX IF NOT EXISTS idx_alertas_id_alerta  ON alertas (id_alerta_soc);
CREATE INDEX IF NOT EXISTS idx_alertas_sede       ON alertas (sede);
CREATE INDEX IF NOT EXISTS idx_alertas_referencia ON alertas (referencia_soc);

-- ----------------------------------------------------------------------------
-- 2. REMITENTES DE CONFIANZA
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remitentes_confianza (
    email       VARCHAR(255) PRIMARY KEY,
    descripcion TEXT
);
INSERT INTO remitentes_confianza (email, descripcion) VALUES
    ('soc-hackaton@sampol.com', 'Buzón emisor del SOC'),
    ('dirti@sampol.com',        'Director de TI (directrices)')
ON CONFLICT (email) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. REGLAS DE CLASIFICACIÓN INCIBE (editables; se evalúan por orden sobre el título)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reglas_clasificacion (
    regla_id       VARCHAR(20) PRIMARY KEY,
    orden          SMALLINT NOT NULL,
    patron         TEXT NOT NULL,          -- regex POSIX sobre el título en minúsculas y sin tildes
    clase_id       VARCHAR(50) NOT NULL REFERENCES incibe_clases(clase_id),
    tipo_id        VARCHAR(50) REFERENCES incibe_tipos(tipo_id),
    estado         estado_alerta_enum,     -- estado que fuerza la regla (NULL = no cambia)
    justificacion  TEXT NOT NULL,
    activa         BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO reglas_clasificacion (regla_id, orden, patron, clase_id, tipo_id, estado, justificacion) VALUES
 ('R01',  10, 'reserva de sala|mantenimiento planificado|consulta administrativa|\mnota [0-9]+', 'OTROS', 'OTROS', 'NO_SOC',
        'Comunicación interna u operativa: no describe un incidente de seguridad.'),
 ('R02',  20, 'solicitud de bloqueo', 'OTROS', 'OTROS', 'EN_REVISION',
        'Solicitud operativa de bloqueo: requiere validar origen y motivo antes de llamar a la API.'),
 ('R03',  30, 'liberacion|desbloqueo', 'OTROS', 'OTROS', 'EN_REVISION',
        'Solicitud operativa de liberación: requiere validar que existe un bloqueo previo y su motivo.'),
 ('R04',  40, 'persistencia dirigida|amenaza persistente|\mapt\M', 'OTROS', 'APT', NULL,
        'Actividad dirigida y persistente atribuible a un actor avanzado (APT).'),
 ('R05',  50, 'infraestructura de mando|mando y control|\mc2\M|c&c|beacon', 'CONTENIDO_DANINO', 'SISTEMA_INFECTADO', NULL,
        'Conexiones periódicas a infraestructura de mando y control: el equipo está infectado.'),
 ('R06',  60, 'configuracion de malware', 'CONTENIDO_DANINO', 'CONFIGURACION_MALWARE', NULL,
        'Recurso que aloja la configuración de un malware.'),
 ('R07',  70, 'carga maliciosa|distribucion de malware|descarga maliciosa', 'CONTENIDO_DANINO', 'DISTRIBUCION_MALWARE', NULL,
        'Un recurso distribuye malware hacia nuestros equipos.'),
 ('R08',  80, 'proceso malicioso|ransomware|cifrado masivo|troyano|malware', 'CONTENIDO_DANINO', 'SISTEMA_INFECTADO', NULL,
        'Ejecución de software malicioso en un equipo propio.'),
 ('R09',  90, 'amplific', 'VULNERABLE', 'AMPLIFICADOR_DDOS', NULL,
        'Servicio expuesto que puede usarse para amplificar ataques DDoS.'),
 ('R10', 100, 'muestra informacion|revelacion de informacion|informacion expuesta', 'VULNERABLE', 'REVELACION_INFORMACION', NULL,
        'Un recurso público revela información interna o de configuración.'),
 ('R11', 110, 'cambio de configuracion|mala configuracion|configuracion erronea', 'DISPONIBILIDAD', 'MALA_CONFIGURACION', NULL,
        'La indisponibilidad la causa un error de configuración, no un ataque.'),
 ('R12', 120, 'cifrado obsoleto|criptografia debil|tls 1\.[01]|ssl', 'VULNERABLE', 'CRIPTOGRAFIA_DEBIL', NULL,
        'Servicio que admite criptografía débil u obsoleta.'),
 ('R13', 130, 'sin restriccion de origen|acceso remoto publicado|expuesto a internet', 'VULNERABLE', 'SERVICIOS_ACCESO_NO_DESEADO', NULL,
        'Servicio publicado con acceso potencial no deseado.'),
 ('R14', 140, 'actualizacion de seguridad pendiente|parche pendiente|sistema vulnerable|cve-', 'VULNERABLE', 'SISTEMA_VULNERABLE', NULL,
        'Sistema con vulnerabilidades conocidas sin corregir.'),
 ('R15', 150, 'trafico distribuido|\mddos\M|denegacion distribuida', 'DISPONIBILIDAD', 'DDOS', NULL,
        'Tráfico desde múltiples orígenes que degrada el servicio (DDoS).'),
 ('R16', 160, 'unico origen|saturacion|denegacion de servicio|\mdos\M', 'DISPONIBILIDAD', 'DOS', NULL,
        'Saturación del servicio desde un único origen (DoS).'),
 ('R17', 170, 'dano deliberado|sabotaje', 'DISPONIBILIDAD', 'SABOTAJE', NULL,
        'Daño intencionado que interrumpe un servicio o equipo.'),
 ('R18', 180, 'interrupcion|caida del enlace|corte de suministro', 'DISPONIBILIDAD', 'INTERRUPCIONES', NULL,
        'Interrupción del servicio por causa externa o fallo.'),
 ('R19', 190, 'cuenta administrativa|cuenta privilegiada|administrador global|cuenta de administrador', 'INTRUSION', 'COMPROMISO_CUENTA_PRIVILEGIADA', NULL,
        'Uso confirmado de una cuenta con privilegios por un tercero.'),
 ('R20', 200, 'no reconoce|cuenta comprometida|acceso correcto', 'INTRUSION', 'COMPROMISO_CUENTA_SIN_PRIVILEGIOS', NULL,
        'Inicio de sesión correcto que el titular no reconoce: cuenta comprometida.'),
 ('R21', 210, 'fuera de su funcion|aplicacion comprometida|webshell', 'INTRUSION', 'COMPROMISO_APLICACIONES', NULL,
        'Una aplicación ejecuta acciones ajenas a su función: aplicación comprometida.'),
 ('R22', 220, 'sustraid|\mrobo\M|\mrobad[oa]s?\M', 'INTRUSION', 'ROBO', NULL,
        'Sustracción física de un equipo o soporte.'),
 ('R23', 230, 'lectura de documentos|fuera de los permisos|acceso no autorizado', 'COMPROMISO_INFORMACION', 'ACCESO_NO_AUTORIZADO', NULL,
        'Acceso a información sin autorización.'),
 ('R24', 240, 'alteracion no autorizada|modificacion no autorizada', 'COMPROMISO_INFORMACION', 'MODIFICACION_NO_AUTORIZADA', NULL,
        'Modificación de información sin autorización.'),
 ('R25', 250, 'datos perdidos|perdida de datos', 'COMPROMISO_INFORMACION', 'PERDIDA_DATOS', NULL,
        'Pérdida de información.'),
 ('R26', 260, 'sondeo|escaneo|barrido de puertos', 'OBTENCION_INFORMACION', 'ESCANEO_REDES', NULL,
        'Reconocimiento de puertos o servicios (scanning).'),
 ('R27', 270, 'captura de trafico|sniff', 'OBTENCION_INFORMACION', 'ANALISIS_PAQUETES', NULL,
        'Captura de tráfico de red (sniffing).'),
 ('R28', 280, 'llamada|ingenieria social|vishing|pretexto', 'OBTENCION_INFORMACION', 'INGENIERIA_SOCIAL', NULL,
        'Intento de obtener información engañando a una persona.'),
 ('R29', 290, 'explotacion|exploit|inyeccion', 'INTENTO_INTRUSION', 'EXPLOTACION_VULNERABILIDADES', NULL,
        'Intento de explotar una vulnerabilidad conocida sin compromiso confirmado.'),
 ('R30', 300, 'accesos fallidos|fuerza bruta|password spray|intentos de acceso', 'INTENTO_INTRUSION', 'INTENTO_ACCESO_CREDENCIALES', NULL,
        'Intentos repetidos de acceso con credenciales sin éxito confirmado.'),
 ('R31', 310, 'no reconocida por firmas|ataque desconocido|secuencia anomala', 'INTENTO_INTRUSION', 'ATAQUE_DESCONOCIDO', NULL,
        'Ataque sin firma conocida.'),
 ('R32', 320, 'recursos de computo|criptomin|uso no autorizado de recursos', 'FRAUDE', 'USO_NO_AUTORIZADO', NULL,
        'Recursos de la empresa usados para fines ajenos al servicio.'),
 ('R33', 330, 'sin licencia|derechos de autor|pirata', 'FRAUDE', 'DERECHOS_AUTOR', NULL,
        'Uso o distribución de software sin licencia.'),
 ('R34', 340, 'suplantacion|cuenta de pago|fraude del ceo', 'FRAUDE', 'SUPLANTACION', NULL,
        'Suplantación de identidad para obtener un beneficio.'),
 ('R35', 350, 'formulario falso|phishing|credenciales falsas', 'FRAUDE', 'PHISHING', NULL,
        'Mensaje que suplanta un servicio para robar credenciales (phishing).'),
 ('R36', 360, 'no solicitados|\mspam\M|correo masivo', 'CONTENIDO_ABUSIVO', 'SPAM', NULL,
        'Envío masivo de mensajes no solicitados.'),
 ('R37', 370, '\modio\M|discrimina', 'CONTENIDO_ABUSIVO', 'DELITO_ODIO', NULL,
        'Contenido de odio.'),
 ('R38', 380, 'contenido sexual|contenido violento', 'CONTENIDO_ABUSIVO', 'CONTENIDO_SEXUAL_VIOLENTO', NULL,
        'Contenido sexual o violento inadecuado.'),
 ('R39', 390, 'comportamiento anomalo|pendiente de caracterizacion', 'OTROS', 'OTROS', 'EN_REVISION',
        'Actividad anómala sin caracterizar: revisión humana necesaria.')
ON CONFLICT (regla_id) DO UPDATE SET orden = EXCLUDED.orden, patron = EXCLUDED.patron, clase_id = EXCLUDED.clase_id,
    tipo_id = EXCLUDED.tipo_id, estado = EXCLUDED.estado, justificacion = EXCLUDED.justificacion;

-- ----------------------------------------------------------------------------
-- 4. FUNCIONES AUXILIARES
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION plegar(p_texto TEXT)
RETURNS TEXT AS $$
    SELECT lower(translate(coalesce(p_texto, ''), 'ÁÉÍÓÚÜÑáéíóúüñ', 'AEIOUUNaeiouun'))
$$ LANGUAGE sql IMMUTABLE;

-- HTML -> texto: celdas separadas por " | " y filas/párrafos por salto de línea
CREATE OR REPLACE FUNCTION texto_plano(p_texto TEXT)
RETURNS TEXT AS $$
    SELECT regexp_replace(regexp_replace(
               replace(replace(replace(replace(replace(
                   regexp_replace(regexp_replace(regexp_replace(regexp_replace(
                       coalesce(p_texto, ''),
                       '<(script|style)[^>]*>.*?</\1>', ' ', 'gi'),
                       '</(td|th)>', ' | ', 'gi'),
                       '<(br|/p|/div|/tr|/li|/h[1-6])[^>]*>', E'\n', 'gi'),
                       '<[^>]+>', ' ', 'g'),
                   '&nbsp;', ' '), '&lt;', '<'), '&gt;', '>'), '&amp;', '&'), '**', ''),
               '[ \t]+', ' ', 'g'),
           '\n\s*\n+', E'\n', 'g')
$$ LANGUAGE sql IMMUTABLE;

-- Valor tras una etiqueta. Las etiquetas se prueban en orden de preferencia:
--   1) al inicio de línea o de celda ("Recurso | srv-01", "ID de alerta: AL-..."), sin distinguir mayúsculas;
--   2) en texto aplanado ("... Recurso srv-01 Sede Palma ..."), solo con la mayúscula de la etiqueta,
--      para no confundir "la fuente" o "estimado equipo" con un campo.
CREATE OR REPLACE FUNCTION extraer_campo(p_texto TEXT, p_etiquetas TEXT, p_valor TEXT DEFAULT '[^|\n]+')
RETURNS TEXT AS $$
DECLARE
    v_etiqueta TEXT;
    v_valor    TEXT;
BEGIN
    FOREACH v_etiqueta IN ARRAY string_to_array(p_etiquetas, '|') LOOP
        v_valor := substring(p_texto FROM '(?i)(?:^|\n|\|)[ \t]*[*-]?[ \t]*(?:' || v_etiqueta
                                         || ')[ \t]*(?::|=|\|)?[ \t]*(' || p_valor || ')');
        IF nullif(btrim(v_valor), '') IS NOT NULL THEN
            RETURN btrim(v_valor);
        END IF;
    END LOOP;
    FOREACH v_etiqueta IN ARRAY string_to_array(p_etiquetas, '|') LOOP
        v_valor := substring(p_texto FROM '(?:^|[[:space:]*])(?:' || v_etiqueta
                                         || ')[ \t]*(?::|=)?[ \t]*(' || p_valor || ')');
        IF nullif(btrim(v_valor), '') IS NOT NULL THEN
            RETURN btrim(v_valor);
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Fecha ISO-8601 a timestamptz (NULL si no es válida)
CREATE OR REPLACE FUNCTION a_fecha(p_texto TEXT)
RETURNS TIMESTAMPTZ AS $$
BEGIN
    RETURN p_texto::timestamptz;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Primera regla activa que encaja con el título
CREATE OR REPLACE FUNCTION clasificar_titulo(p_titulo TEXT)
RETURNS reglas_clasificacion AS $$
    SELECT r.* FROM reglas_clasificacion r
    WHERE r.activa AND plegar(p_titulo) ~ r.patron
    ORDER BY r.orden
    LIMIT 1
$$ LANGUAGE sql STABLE;

-- ----------------------------------------------------------------------------
-- 5. PROCESADO DE UN CORREO DE LA BANDEJA (lo llama el trigger y se puede re-ejecutar)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION procesar_correo(p_correo_id UUID)
RETURNS JSONB AS $$
DECLARE
    r              bandeja_entrada%ROWTYPE;
    v_texto        TEXT;
    v_sospecha     TEXT;
    v_remitente    TEXT;
    v_confianza    BOOLEAN;
    v_prioridad    prioridad_soc_enum;
    v_peligrosidad peligrosidad_soc_enum;
    v_titulo       TEXT;
    v_equipo       TEXT;
    v_usuario      TEXT;
    v_fuente       TEXT;
    v_ip_txt       TEXT;
    v_ip           INET;
    v_sede         TEXT;
    v_regla_det    TEXT;
    v_criticidad   TEXT;
    v_id_alerta    TEXT;
    v_referencia   TEXT;
    v_solicitud    TEXT;
    v_f_primero    TEXT;
    v_f_ultimo     TEXT;
    v_f_emision    TEXT;
    v_fecha_evento TIMESTAMPTZ;
    v_zona         TEXT;
    v_inconsist    TEXT[] := '{}';
    v_clave        TEXT;
    v_hash         VARCHAR(64);
    v_original     alertas%ROWTYPE;
    v_hay_original BOOLEAN := FALSE;
    v_intercambio  BOOLEAN := FALSE;
    v_regla        reglas_clasificacion%ROWTYPE;
    v_clase        VARCHAR(50);
    v_tipo         VARCHAR(50);
    v_justif       TEXT;
    v_estado       estado_alerta_enum;
    v_alerta_id    UUID := gen_random_uuid();
BEGIN
    SELECT * INTO r FROM bandeja_entrada WHERE correo_id = p_correo_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('resultado', 'NO_ENCONTRADO');
    END IF;
    IF EXISTS (SELECT 1 FROM alertas WHERE correo_id = p_correo_id)
       OR EXISTS (SELECT 1 FROM correos_malformados WHERE correo_id = p_correo_id) THEN
        RETURN jsonb_build_object('resultado', 'YA_PROCESADO');
    END IF;

    v_texto     := texto_plano(r.cuerpo_correo_raw);
    v_remitente := lower(coalesce(substring(r.remitente_correo FROM '([[:alnum:]._%+-]+@[[:alnum:].-]+)'), r.remitente_correo));
    v_confianza := EXISTS (SELECT 1 FROM remitentes_confianza WHERE lower(email) = v_remitente);
    v_sospecha  := concat_ws('; ',
                       motivo_sospecha_ia(r.asunto_correo, v_texto),
                       CASE WHEN NOT v_confianza THEN 'Remitente fuera de la lista de confianza (' || v_remitente || ')' END);
    v_sospecha  := nullif(v_sospecha, '');

    -- Nomenclatura esperada: [SOC][Px][GRAVEDAD] Título
    IF r.asunto_correo !~* '^\s*\[SOC\]\s*\[P[1-4]\]\s*\[(INFORMATIV[OA]|BAJ[OA]|MEDI[OA]|ALT[OA]|CR[IÍ]TIC[OA])\]' THEN
        INSERT INTO correos_malformados (
            correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, motivo_descarte, es_sospechoso, motivo_sospecha
        ) VALUES (
            r.correo_id, r.id_mensaje_correo, r.remitente_correo, r.asunto_correo,
            r.cuerpo_correo_raw, r.fecha_hora_correo,
            'El asunto no sigue la nomenclatura requerida: [SOC][Px][PELIGROSIDAD]',
            v_sospecha IS NOT NULL, v_sospecha
        );
        RETURN jsonb_build_object('resultado', 'MALFORMADO');
    END IF;

    BEGIN
        -- Asunto
        v_prioridad    := upper(substring(r.asunto_correo FROM '(?i)\[(P[1-4])\]'))::prioridad_soc_enum;
        v_peligrosidad := CASE left(plegar(substring(r.asunto_correo
                              FROM '(?i)\[(INFORMATIV[OA]|BAJ[OA]|MEDI[OA]|ALT[OA]|CR[IÍ]TIC[OA])\]')), 4)
                              WHEN 'info' THEN 'INFORMATIVO' WHEN 'baja' THEN 'BAJO' WHEN 'bajo' THEN 'BAJO'
                              WHEN 'medi' THEN 'MEDIO' WHEN 'alta' THEN 'ALTO' WHEN 'alto' THEN 'ALTO'
                              ELSE 'CRITICO' END::peligrosidad_soc_enum;
        v_titulo := btrim(regexp_replace(r.asunto_correo, '^\s*(\[[^]]*\]\s*){3}', ''));

        -- Identificadores
        v_id_alerta  := coalesce(extraer_campo(v_texto, 'ID de alerta|Id\. de alerta|Alerta', 'AL-[0-9]{8}-[0-9]+'),
                                 substring(r.asunto_correo FROM '\m(AL-[0-9]{8}-[0-9]+)\M'));
        v_solicitud  := substring(r.asunto_correo FROM '\m(SOL-[BL]-[0-9]+)\M');
        v_referencia := substring(r.asunto_correo || ' ' || v_texto FROM '\m(SOC-[0-9]{8}-[0-9]{3}-[A-Za-z0-9]+)\M');

        -- Campos de la tabla del cuerpo
        v_equipo := coalesce(
            extraer_campo(v_texto, 'Recurso|Equipo afectado|Equipo|Hostname|Host|Servidor|Activo|Dispositivo', '[A-Za-z0-9][A-Za-z0-9._-]*'),
            substring(v_texto FROM '(?i)\m((?:pc|srv|fw|dc|sw|ap|nas|vpn|plc|scada|web|mail)-[a-z0-9-]+)\M'));
        IF v_equipo ~* '^(no|n/a|ninguno|desconocido)$' THEN v_equipo := NULL; END IF;

        v_usuario := extraer_campo(v_texto, 'Cuenta relacionada|Cuenta privilegiada|Usuario afectado|Usuario implicado|Usuario|Cuenta', '[^|\n ]+');
        IF v_usuario IS NOT NULL AND v_usuario !~ '@|^[A-Za-z0-9._-]{2,}$' OR plegar(v_usuario) IN ('no', 'n/a', 'ninguna', 'ninguno', 'sin') THEN
            v_usuario := NULL;
        END IF;

        v_ip_txt := extraer_campo(v_texto, 'Direcci[oó]n relacionada|Direcci[oó]n IP|IP de origen|IP origen|IP afectada|IP', '[0-9A-Fa-f:.]{3,45}');
        BEGIN
            v_ip := v_ip_txt::inet;
        EXCEPTION WHEN others THEN
            v_ip := NULL;
            IF v_ip_txt IS NOT NULL THEN
                v_inconsist := v_inconsist || ('Dirección relacionada con formato no válido: ' || v_ip_txt);
            END IF;
        END;
        IF v_ip IS NULL AND v_ip_txt IS NULL THEN
            v_ip := substring(v_texto FROM '\m((?:[0-9]{1,3}\.){3}[0-9]{1,3})\M')::inet;
        END IF;

        v_fuente     := left(btrim(extraer_campo(v_texto, 'Fuente|Herramienta|Source|Sensor', '[^|\n]{2,80}?(?=\s*(?:\||\n|Regla de detecci|$))')), 100);
        v_regla_det  := extraer_campo(v_texto, 'Regla de detecci[oó]n|Regla', '[A-Za-z0-9][A-Za-z0-9._-]*');
        v_sede       := extraer_campo(v_texto, 'Sede|Ubicaci[oó]n|Centro', '[[:alpha:]]+');
        v_criticidad := extraer_campo(v_texto, 'Criticidad|Severidad|Gravedad', '(?:Cr[ií]tic[ao]|Alt[ao]|Medi[ao]|Baj[ao]|Informativ[ao])');

        -- Fechas (ISO-8601)
        v_f_primero := extraer_campo(v_texto, 'Primer evento|Fecha del evento|Fecha y hora|Fecha|Timestamp',
                                     '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+(?:Z|[+-][0-9]{2}:?[0-9]{2})?');
        v_f_ultimo  := extraer_campo(v_texto, '[UÚ]ltimo evento', '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+(?:Z|[+-][0-9]{2}:?[0-9]{2})?');
        v_f_emision := extraer_campo(v_texto, 'Emisi[oó]n', '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+(?:Z|[+-][0-9]{2}:?[0-9]{2})?');
        v_fecha_evento := a_fecha(v_f_primero);
        v_zona := CASE WHEN v_fecha_evento IS NULL THEN NULL
                       WHEN v_f_primero ~ '(Z|[+-][0-9]{2}:?[0-9]{2})$' THEN substring(v_f_primero FROM '(Z|[+-][0-9]{2}:?[0-9]{2})$')
                       ELSE 'SIN_ZONA (interpretada como UTC)' END;

        -- Inconsistencias (trampas del buzón)
        IF v_criticidad IS NOT NULL AND left(plegar(v_criticidad), 3) <> left(plegar(v_peligrosidad::text), 3) THEN
            v_inconsist := v_inconsist || ('Gravedad del asunto ' || v_peligrosidad || ' distinta de la criticidad del cuerpo ' || v_criticidad);
        END IF;
        IF (v_prioridad IN ('P3', 'P4') AND v_peligrosidad IN ('ALTO', 'CRITICO'))
           OR (v_prioridad = 'P1' AND v_peligrosidad IN ('INFORMATIVO', 'BAJO')) THEN
            v_inconsist := v_inconsist || ('Prioridad ' || v_prioridad || ' incoherente con gravedad ' || v_peligrosidad);
        END IF;
        IF v_fecha_evento IS NOT NULL AND v_fecha_evento > r.fecha_hora_correo + INTERVAL '5 minutes' THEN
            v_inconsist := v_inconsist || 'Fecha del evento posterior a la recepción del correo';
        END IF;

        -- Duplicados: mismo ID de alerta o de solicitud; si no hay, huella del contenido en 24 h
        v_clave := CASE WHEN v_solicitud IS NOT NULL THEN 'SOL|' || v_solicitud
                        WHEN v_id_alerta IS NOT NULL THEN 'AL|' || v_id_alerta
                        ELSE 'HASH|' || lower(concat_ws('|', v_titulo, v_equipo, v_ip::text, v_usuario,
                                 CASE WHEN v_equipo IS NULL AND v_ip IS NULL AND v_usuario IS NULL
                                      THEN regexp_replace(v_texto, '\s+', ' ', 'g') END)) END;
        v_hash := encode(sha256(convert_to(v_clave, 'UTF8')), 'hex');

        SELECT * INTO v_original FROM alertas
        WHERE hash_contenido = v_hash AND NOT es_duplicada
          AND (v_clave NOT LIKE 'HASH|%'
               OR fecha_hora_correo BETWEEN r.fecha_hora_correo - INTERVAL '24 hours' AND r.fecha_hora_correo + INTERVAL '24 hours')
        ORDER BY fecha_hora_correo
        LIMIT 1;
        v_hay_original := FOUND;
        -- Si el que llega ahora es más antiguo, pasa a ser el original
        v_intercambio := v_hay_original AND v_original.fecha_hora_correo > r.fecha_hora_correo;

        -- Clasificación INCIBE
        IF v_hay_original AND NOT v_intercambio AND v_original.incibe_clase_id IS NOT NULL THEN
            v_clase  := v_original.incibe_clase_id;
            v_tipo   := v_original.incibe_tipo_id;
            v_justif := 'Duplicado de ' || coalesce(v_original.referencia_soc, v_original.alerta_id::text)
                        || ' (' || coalesce(v_id_alerta, v_solicitud, 'mismo contenido') || '): hereda su categoría.';
        ELSE
            v_regla := clasificar_titulo(v_titulo);
            IF v_regla.regla_id IS NOT NULL THEN
                v_clase  := v_regla.clase_id;
                v_tipo   := v_regla.tipo_id;
                v_justif := 'Regla ' || v_regla.regla_id || ': ' || v_regla.justificacion;
            ELSE
                v_justif := 'Ninguna regla encaja con el título: revisión humana necesaria.';
            END IF;
        END IF;

        v_estado := CASE WHEN v_sospecha IS NOT NULL THEN 'EN_REVISION'
                         WHEN v_regla.estado IS NOT NULL THEN v_regla.estado
                         WHEN v_clase IS NULL THEN 'EN_REVISION'
                         WHEN v_hay_original AND NOT v_intercambio THEN v_original.estado
                         ELSE 'NUEVA' END;

        INSERT INTO alertas (
            alerta_id, correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, soc_prioridad, soc_peligrosidad,
            titulo, descripcion, fuente_herramienta, equipo_afectado, ip_afectada, ip_raw, usuario_implicado,
            sede, regla_deteccion, criticidad_cuerpo, id_alerta_soc, referencia_soc, id_solicitud,
            fecha_hora_evento, fecha_evento_raw, zona_horaria_original, fecha_ultimo_evento, fecha_emision,
            incibe_clase_id, incibe_tipo_id, justificacion_categoria, metodo_categorizacion, regla_id,
            hash_contenido, alerta_original_id, es_duplicada,
            es_sospechosa, motivo_sospecha, remitente_confianza, inconsistencias, estado
        ) VALUES (
            v_alerta_id, r.correo_id, r.id_mensaje_correo, r.remitente_correo, r.asunto_correo,
            r.cuerpo_correo_raw, r.fecha_hora_correo, v_prioridad, v_peligrosidad,
            v_titulo, left(btrim(v_texto), 4000), v_fuente, v_equipo, v_ip, v_ip_txt, v_usuario,
            v_sede, v_regla_det, v_criticidad, v_id_alerta, v_referencia, v_solicitud,
            v_fecha_evento, v_f_primero, v_zona, a_fecha(v_f_ultimo), a_fecha(v_f_emision),
            v_clase, v_tipo, v_justif, 'REGLAS', v_regla.regla_id,
            v_hash,
            CASE WHEN v_hay_original AND NOT v_intercambio THEN v_original.alerta_id END,
            v_hay_original AND NOT v_intercambio,
            v_sospecha IS NOT NULL, v_sospecha, v_confianza, v_inconsist, v_estado
        );

        IF v_intercambio THEN
            UPDATE alertas SET alerta_original_id = v_alerta_id, es_duplicada = TRUE
            WHERE alerta_id = v_original.alerta_id OR alerta_original_id = v_original.alerta_id;
        END IF;

        RETURN jsonb_build_object('resultado', CASE WHEN v_hay_original AND NOT v_intercambio THEN 'DUPLICADA' ELSE 'ALERTA' END,
                                  'alerta_id', v_alerta_id);
    EXCEPTION WHEN others THEN
        -- Nunca se pierde un correo: si algo falla al procesarlo, queda para revisión manual
        INSERT INTO correos_malformados (
            correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, motivo_descarte, es_sospechoso, motivo_sospecha
        ) VALUES (
            r.correo_id, r.id_mensaje_correo, r.remitente_correo, r.asunto_correo,
            r.cuerpo_correo_raw, r.fecha_hora_correo,
            'Error al procesar: ' || SQLERRM, v_sospecha IS NOT NULL, v_sospecha
        );
        RETURN jsonb_build_object('resultado', 'MALFORMADO', 'error', SQLERRM);
    END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trg_procesar_correo_entrante()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM procesar_correo(NEW.correo_id);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Procesa los correos de la bandeja que aún no tengan alerta ni descarte
CREATE OR REPLACE FUNCTION procesar_pendientes()
RETURNS INTEGER AS $$
DECLARE
    v_id UUID;
    n    INTEGER := 0;
BEGIN
    FOR v_id IN
        SELECT b.correo_id FROM bandeja_entrada b
        WHERE NOT EXISTS (SELECT 1 FROM alertas a WHERE a.correo_id = b.correo_id)
          AND NOT EXISTS (SELECT 1 FROM correos_malformados m WHERE m.correo_id = b.correo_id)
        ORDER BY b.fecha_hora_correo
    LOOP
        PERFORM procesar_correo(v_id);
        n := n + 1;
    END LOOP;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

-- Vuelve a aplicar las reglas (tras editarlas) a las alertas no revisadas por una persona
CREATE OR REPLACE FUNCTION reaplicar_reglas()
RETURNS INTEGER AS $$
DECLARE
    n INTEGER;
BEGIN
    UPDATE alertas a
    SET incibe_clase_id = c.clase_id, incibe_tipo_id = c.tipo_id, regla_id = c.regla_id,
        justificacion_categoria = 'Regla ' || c.regla_id || ': ' || c.justificacion
    FROM (SELECT x.alerta_id, (clasificar_titulo(x.titulo)).* FROM alertas x) c
    WHERE c.alerta_id = a.alerta_id
      AND NOT a.es_duplicada
      AND NOT coalesce(a.revisado_por_humano, FALSE)
      AND a.metodo_categorizacion = 'REGLAS'
      AND c.regla_id IS NOT NULL
      AND c.regla_id IS DISTINCT FROM a.regla_id;
    GET DIAGNOSTICS n = ROW_COUNT;
    -- Los duplicados heredan la categoría de su original
    UPDATE alertas d SET incibe_clase_id = o.incibe_clase_id, incibe_tipo_id = o.incibe_tipo_id
    FROM alertas o
    WHERE d.alerta_original_id = o.alerta_id
      AND (d.incibe_clase_id IS DISTINCT FROM o.incibe_clase_id OR d.incibe_tipo_id IS DISTINCT FROM o.incibe_tipo_id);
    RETURN n;
END;
$$ LANGUAGE plpgsql;
