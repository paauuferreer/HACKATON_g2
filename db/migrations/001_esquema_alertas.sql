-- ============================================================================
-- 001_esquema_alertas.sql — Esquema del equipo (basado en "Creacion base de datos", reparado)
-- Motor: PostgreSQL 18 (Azure). Idempotente: se puede ejecutar varias veces.
--
-- Cambios respecto al script original:
--   * Sin DROP/TRUNCATE: no borra datos al re-ejecutarse.
--   * Bloques $$ reconstruidos (Google Docs los había convertido en ecuaciones).
--   * bandeja_entrada: correo original íntegro e inmutable. Power Automate solo
--     tiene que hacer "Insertar fila" aquí; un trigger lo enruta a alertas o a
--     correos_malformados (misma lógica que registrar_correo_entrante()).
--   * alertas: + fuente, equipo, IP, usuario, fecha del evento, descripción,
--     sospecha (prompt injection) y enlace al correo original.
--   * Duplicados: huella de (asunto sin etiquetas, equipo, IP, usuario) en 24 h,
--     y ahora sí se rellenan alerta_original_id / es_duplicada.
--   * Taxonomía INCIBE oficial (10 clases, 36 tipos) y escalas de impacto y
--     peligrosidad de la guía.
--   * acciones_bloqueo: registro de llamadas a la API /bloquear y /liberar.
--   * gen_random_uuid() en lugar de uuid_generate_v4(): Azure no permite "uuid-ossp".
-- ============================================================================

-- Sin extensiones: Azure no permite uuid-ossp; gen_random_uuid() y sha256() son nativas en PG 13+/11+.

-- ----------------------------------------------------------------------------
-- 1. TIPOS ENUMERADOS (CREATE TYPE no admite IF NOT EXISTS)
-- ----------------------------------------------------------------------------
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'estado_alerta_enum') THEN
        CREATE TYPE estado_alerta_enum AS ENUM
            ('NUEVA', 'EN_REVISION', 'CONFIRMADA', 'FALSA_ALARMA', 'NO_SOC', 'CERRADA');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'prioridad_soc_enum') THEN
        CREATE TYPE prioridad_soc_enum AS ENUM ('P1', 'P2', 'P3', 'P4');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'peligrosidad_soc_enum') THEN
        CREATE TYPE peligrosidad_soc_enum AS ENUM ('INFORMATIVO', 'BAJO', 'MEDIO', 'ALTO', 'CRITICO');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'origen_categorizacion_enum') THEN
        CREATE TYPE origen_categorizacion_enum AS ENUM ('REGLAS', 'IA', 'HIBRIDO', 'HUMANO');
    END IF;
    -- Escala de impacto de la guía INCIBE
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nivel_impacto_enum') THEN
        CREATE TYPE nivel_impacto_enum AS ENUM ('SIN_IMPACTO', 'BAJO', 'MEDIO', 'ALTO', 'MUY_ALTO', 'CRITICO');
    END IF;
    -- Escala de peligrosidad de la guía INCIBE (distinta de la gravedad que pone el SOC)
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'peligrosidad_incibe_enum') THEN
        CREATE TYPE peligrosidad_incibe_enum AS ENUM ('BAJO', 'MEDIO', 'ALTO', 'MUY_ALTO', 'CRITICO');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'estado_malformado_enum') THEN
        CREATE TYPE estado_malformado_enum AS ENUM ('PENDIENTE_REVISION', 'PROCESADO_MANUALMENTE', 'DESCARTADO');
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 2. TABLAS MAESTRAS (TAXONOMÍA INCIBE — Guía nacional de notificación y gestión de ciberincidentes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incibe_clases (
    clase_id    VARCHAR(50) PRIMARY KEY,
    nombre      VARCHAR(100) NOT NULL,
    descripcion TEXT,
    orden       SMALLINT
);

CREATE TABLE IF NOT EXISTS incibe_tipos (
    tipo_id     VARCHAR(50) PRIMARY KEY,
    clase_id    VARCHAR(50) NOT NULL REFERENCES incibe_clases(clase_id) ON DELETE CASCADE,
    nombre      VARCHAR(150) NOT NULL,
    descripcion TEXT
);

INSERT INTO incibe_clases (clase_id, nombre, descripcion, orden) VALUES
    ('CONTENIDO_ABUSIVO',      'Contenido abusivo',            'Spam y contenidos ofensivos o ilícitos', 1),
    ('CONTENIDO_DANINO',       'Contenido dañino',             'Malware de cualquier tipo', 2),
    ('OBTENCION_INFORMACION',  'Obtención de información',     'Escaneos, monitorización de tráfico, ingeniería social', 3),
    ('INTENTO_INTRUSION',      'Intento de intrusión',         'Explotación de vulnerabilidades e intentos de acceso', 4),
    ('INTRUSION',              'Intrusión',                    'Compromiso de cuentas o de aplicaciones', 5),
    ('DISPONIBILIDAD',         'Disponibilidad',               'Denegación de servicio, sabotaje e interrupciones', 6),
    ('COMPROMISO_INFORMACION', 'Compromiso de la información', 'Acceso o modificación no autorizados y pérdida de datos', 7),
    ('FRAUDE',                 'Fraude',                       'Phishing, suplantación y uso no autorizado de recursos', 8),
    ('VULNERABLE',             'Vulnerable',                   'Sistemas o servicios con debilidades expuestas', 9),
    ('OTROS',                  'Otros',                        'Lo que no encaja en ninguna de las anteriores', 10)
ON CONFLICT (clase_id) DO UPDATE
    SET nombre = EXCLUDED.nombre, descripcion = EXCLUDED.descripcion, orden = EXCLUDED.orden;

INSERT INTO incibe_tipos (tipo_id, clase_id, nombre) VALUES
    ('SPAM',                        'CONTENIDO_ABUSIVO',      'Spam'),
    ('DELITO_ODIO',                 'CONTENIDO_ABUSIVO',      'Delito de odio'),
    ('CONTENIDO_SEXUAL_VIOLENTO',   'CONTENIDO_ABUSIVO',      'Pornografía infantil, contenido sexual o violento inadecuado'),
    ('SISTEMA_INFECTADO',           'CONTENIDO_DANINO',       'Sistema infectado'),
    ('SERVIDOR_CC',                 'CONTENIDO_DANINO',       'Servidor C&C'),
    ('DISTRIBUCION_MALWARE',        'CONTENIDO_DANINO',       'Distribución de malware'),
    ('CONFIGURACION_MALWARE',       'CONTENIDO_DANINO',       'Configuración de malware'),
    ('ESCANEO_REDES',               'OBTENCION_INFORMACION',  'Escaneo de redes (scanning)'),
    ('ANALISIS_PAQUETES',           'OBTENCION_INFORMACION',  'Análisis de paquetes (sniffing)'),
    ('INGENIERIA_SOCIAL',           'OBTENCION_INFORMACION',  'Ingeniería social'),
    ('EXPLOTACION_VULNERABILIDADES','INTENTO_INTRUSION',      'Explotación de vulnerabilidades conocidas'),
    ('INTENTO_ACCESO_CREDENCIALES', 'INTENTO_INTRUSION',      'Intento de acceso con vulneración de credenciales'),
    ('ATAQUE_DESCONOCIDO',          'INTENTO_INTRUSION',      'Ataque desconocido'),
    ('COMPROMISO_CUENTA_PRIVILEGIADA','INTRUSION',            'Compromiso de cuenta con privilegios'),
    ('COMPROMISO_CUENTA_SIN_PRIVILEGIOS','INTRUSION',         'Compromiso de cuenta sin privilegios'),
    ('COMPROMISO_APLICACIONES',     'INTRUSION',              'Compromiso de aplicaciones'),
    ('ROBO',                        'INTRUSION',              'Robo'),
    ('DOS',                         'DISPONIBILIDAD',         'DoS (denegación de servicio)'),
    ('DDOS',                        'DISPONIBILIDAD',         'DDoS (denegación distribuida de servicio)'),
    ('MALA_CONFIGURACION',          'DISPONIBILIDAD',         'Mala configuración'),
    ('SABOTAJE',                    'DISPONIBILIDAD',         'Sabotaje'),
    ('INTERRUPCIONES',              'DISPONIBILIDAD',         'Interrupciones'),
    ('ACCESO_NO_AUTORIZADO',        'COMPROMISO_INFORMACION', 'Acceso no autorizado a información'),
    ('MODIFICACION_NO_AUTORIZADA',  'COMPROMISO_INFORMACION', 'Modificación no autorizada de información'),
    ('PERDIDA_DATOS',               'COMPROMISO_INFORMACION', 'Pérdida de datos'),
    ('USO_NO_AUTORIZADO',           'FRAUDE',                 'Uso no autorizado de recursos'),
    ('DERECHOS_AUTOR',              'FRAUDE',                 'Derechos de autor'),
    ('SUPLANTACION',                'FRAUDE',                 'Suplantación'),
    ('PHISHING',                    'FRAUDE',                 'Phishing'),
    ('CRIPTOGRAFIA_DEBIL',          'VULNERABLE',             'Criptografía débil'),
    ('AMPLIFICADOR_DDOS',           'VULNERABLE',             'Amplificador DDoS'),
    ('SERVICIOS_ACCESO_NO_DESEADO', 'VULNERABLE',             'Servicios con acceso potencial no deseado'),
    ('REVELACION_INFORMACION',      'VULNERABLE',             'Revelación de información'),
    ('SISTEMA_VULNERABLE',          'VULNERABLE',             'Sistema vulnerable'),
    ('APT',                         'OTROS',                  'APT'),
    ('OTROS',                       'OTROS',                  'Otros')
ON CONFLICT (tipo_id) DO UPDATE SET clase_id = EXCLUDED.clase_id, nombre = EXCLUDED.nombre;

-- ----------------------------------------------------------------------------
-- 3. BANDEJA DE ENTRADA: correo original íntegro e inmutable (prueba de qué llegó y cuándo)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bandeja_entrada (
    correo_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_mensaje_correo  VARCHAR(255) NOT NULL UNIQUE,     -- Id / InternetMessageId de Outlook
    remitente_correo   VARCHAR(255) NOT NULL,
    destinatarios      TEXT,
    asunto_correo      VARCHAR(500) NOT NULL DEFAULT '',
    cuerpo_correo_raw  TEXT NOT NULL DEFAULT '',          -- tal cual (puede ser HTML)
    cabeceras          JSONB,                             -- si se pueden obtener (SPF, DKIM, Received...)
    adjuntos           JSONB,                             -- [{nombre, tipo, tamano, contenido_base64?}]
    eml_raw            TEXT,                              -- "Exportar correo" de Power Automate, si se usa
    fecha_hora_correo  TIMESTAMP WITH TIME ZONE NOT NULL, -- hora exacta de llegada
    canal              VARCHAR(30) NOT NULL DEFAULT 'POWER_AUTOMATE',
    hash_correo        VARCHAR(64),                       -- sha256 del contenido (lo calcula el trigger)
    fecha_recepcion_bd TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bandeja_fecha ON bandeja_entrada (fecha_hora_correo DESC);

-- ----------------------------------------------------------------------------
-- 4. TABLA PRINCIPAL DE ALERTAS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alertas (
    alerta_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correo_id UUID REFERENCES bandeja_entrada(correo_id),

    -- Datos del correo original
    id_mensaje_correo  VARCHAR(255) UNIQUE,
    remitente_correo   VARCHAR(255) NOT NULL,
    asunto_correo      VARCHAR(500) NOT NULL,
    cuerpo_correo_raw  TEXT NOT NULL,
    fecha_hora_correo  TIMESTAMP WITH TIME ZONE NOT NULL,   -- hora exacta de llegada del correo

    -- Campos extraídos del asunto SOC
    soc_prioridad      prioridad_soc_enum NOT NULL,
    soc_peligrosidad   peligrosidad_soc_enum NOT NULL,

    -- Campos extraídos del cuerpo (mejor esfuerzo; NULL si no aparecen)
    titulo                VARCHAR(500),                     -- asunto sin las etiquetas [SOC][Px][...]
    descripcion           TEXT,
    fuente_herramienta    VARCHAR(100),
    equipo_afectado       VARCHAR(255),
    ip_afectada           INET,
    usuario_implicado     VARCHAR(255),
    fecha_hora_evento     TIMESTAMP WITH TIME ZONE,         -- hora del hecho, normalizada
    fecha_evento_raw      VARCHAR(100),                     -- tal como venía
    zona_horaria_original VARCHAR(50),

    -- Categorización INCIBE
    incibe_clase_id         VARCHAR(50) REFERENCES incibe_clases(clase_id),
    incibe_tipo_id          VARCHAR(50) REFERENCES incibe_tipos(tipo_id),
    justificacion_categoria TEXT,
    metodo_categorizacion   origen_categorizacion_enum DEFAULT 'REGLAS',
    impacto_incibe          nivel_impacto_enum,
    peligrosidad_incibe     peligrosidad_incibe_enum,

    -- Estado y control de duplicados
    estado             estado_alerta_enum NOT NULL DEFAULT 'NUEVA',
    hash_contenido     VARCHAR(64) NOT NULL,
    alerta_original_id UUID REFERENCES alertas(alerta_id),
    es_duplicada       BOOLEAN NOT NULL DEFAULT FALSE,

    -- Correo manipulado / instrucciones dirigidas a una IA
    es_sospechosa      BOOLEAN NOT NULL DEFAULT FALSE,
    motivo_sospecha    TEXT,

    -- Revisión humana y auditoría
    revisado_por_humano   BOOLEAN DEFAULT FALSE,
    usuario_analista      VARCHAR(100),
    fecha_ultima_revision TIMESTAMP WITH TIME ZONE,
    notas_analista        TEXT,

    fecha_registro_bd   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_duplicada CHECK (es_duplicada = (alerta_original_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_alertas_fecha_correo ON alertas (fecha_hora_correo DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_prioridad_peligrosidad ON alertas (soc_prioridad, soc_peligrosidad);
CREATE INDEX IF NOT EXISTS idx_alertas_hash ON alertas (hash_contenido);
CREATE INDEX IF NOT EXISTS idx_alertas_estado ON alertas (estado);
CREATE INDEX IF NOT EXISTS idx_alertas_equipo ON alertas (lower(equipo_afectado));
CREATE INDEX IF NOT EXISTS idx_alertas_usuario ON alertas (lower(usuario_implicado));
CREATE INDEX IF NOT EXISTS idx_alertas_ip ON alertas (ip_afectada);
CREATE INDEX IF NOT EXISTS idx_alertas_original ON alertas (alerta_original_id);

-- ----------------------------------------------------------------------------
-- 5. CORREOS MALFORMADOS / NO CONFORMES
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correos_malformados (
    descarte_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correo_id   UUID REFERENCES bandeja_entrada(correo_id),

    id_mensaje_correo VARCHAR(255) UNIQUE,
    remitente_correo  VARCHAR(255) NOT NULL,
    asunto_correo     VARCHAR(500) NOT NULL,
    cuerpo_correo_raw TEXT NOT NULL,
    fecha_hora_correo TIMESTAMP WITH TIME ZONE NOT NULL,

    motivo_descarte      TEXT NOT NULL,
    es_sospechoso        BOOLEAN NOT NULL DEFAULT FALSE,
    motivo_sospecha      TEXT,
    estado               estado_malformado_enum NOT NULL DEFAULT 'PENDIENTE_REVISION',
    revisado_por         VARCHAR(100),
    fecha_revision       TIMESTAMP WITH TIME ZONE,
    alerta_convertida_id UUID REFERENCES alertas(alerta_id),

    fecha_recepcion_bd TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_malformados_estado ON correos_malformados (estado);
CREATE INDEX IF NOT EXISTS idx_malformados_fecha ON correos_malformados (fecha_hora_correo DESC);

-- ----------------------------------------------------------------------------
-- 6. AUDITORÍA E HISTORIAL DE CAMBIOS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS historial_cambios_alertas (
    historial_id         BIGSERIAL PRIMARY KEY,
    alerta_id            UUID NOT NULL REFERENCES alertas(alerta_id) ON DELETE CASCADE,
    usuario              VARCHAR(100) NOT NULL DEFAULT 'SISTEMA',
    campo_modificado     VARCHAR(100) NOT NULL,
    valor_anterior       TEXT,
    valor_nuevo          TEXT,
    justificacion_cambio TEXT,
    fecha_registro       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_historial_alerta ON historial_cambios_alertas (alerta_id);

-- ----------------------------------------------------------------------------
-- 7. ACCIONES CONTRA LA API DE BLOQUEO (/equipo-2/bloquear y /liberar)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acciones_bloqueo (
    accion_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    accion           VARCHAR(10) NOT NULL CHECK (accion IN ('BLOQUEAR', 'LIBERAR')),
    usuario_objetivo VARCHAR(255),
    ip_objetivo      INET,
    motivo           TEXT NOT NULL,
    regla            VARCHAR(100),
    alerta_id        UUID REFERENCES alertas(alerta_id),
    solicitado_por   VARCHAR(100) NOT NULL DEFAULT 'SISTEMA',
    simulacion       BOOLEAN NOT NULL DEFAULT FALSE,
    http_status      INTEGER,
    respuesta_api    JSONB,
    exito            BOOLEAN,
    fecha_solicitud  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fecha_respuesta  TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_objetivo CHECK (usuario_objetivo IS NOT NULL OR ip_objetivo IS NOT NULL)
);

-- ----------------------------------------------------------------------------
-- 8. TRIGGERS DE ALERTAS (reconstruidos del script original)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.fecha_actualizacion = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_timestamp ON alertas;
CREATE TRIGGER trigger_update_timestamp
    BEFORE UPDATE ON alertas
    FOR EACH ROW EXECUTE FUNCTION trg_update_timestamp();

-- El tipo INCIBE tiene que pertenecer a la clase elegida
CREATE OR REPLACE FUNCTION trg_validar_tipo_incibe()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.incibe_tipo_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM incibe_tipos
        WHERE tipo_id = NEW.incibe_tipo_id AND clase_id = NEW.incibe_clase_id) THEN
        RAISE EXCEPTION 'El tipo % no pertenece a la clase %', NEW.incibe_tipo_id, NEW.incibe_clase_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_validar_tipo_incibe ON alertas;
CREATE TRIGGER trigger_validar_tipo_incibe
    BEFORE INSERT OR UPDATE OF incibe_clase_id, incibe_tipo_id ON alertas
    FOR EACH ROW EXECUTE FUNCTION trg_validar_tipo_incibe();

-- Auditar cambios de estado y de categoría
CREATE OR REPLACE FUNCTION trg_auditar_cambios_alerta()
RETURNS TRIGGER AS $$
DECLARE
    usuario_act VARCHAR(100);
BEGIN
    usuario_act := COALESCE(NEW.usuario_analista, 'SISTEMA');

    IF (OLD.estado IS DISTINCT FROM NEW.estado) THEN
        INSERT INTO historial_cambios_alertas (alerta_id, usuario, campo_modificado, valor_anterior, valor_nuevo)
        VALUES (NEW.alerta_id, usuario_act, 'estado', OLD.estado::text, NEW.estado::text);
    END IF;

    IF (OLD.incibe_clase_id IS DISTINCT FROM NEW.incibe_clase_id) THEN
        INSERT INTO historial_cambios_alertas (alerta_id, usuario, campo_modificado, valor_anterior, valor_nuevo, justificacion_cambio)
        VALUES (NEW.alerta_id, usuario_act, 'incibe_clase_id', OLD.incibe_clase_id, NEW.incibe_clase_id, NEW.justificacion_categoria);
    END IF;

    IF (OLD.incibe_tipo_id IS DISTINCT FROM NEW.incibe_tipo_id) THEN
        INSERT INTO historial_cambios_alertas (alerta_id, usuario, campo_modificado, valor_anterior, valor_nuevo, justificacion_cambio)
        VALUES (NEW.alerta_id, usuario_act, 'incibe_tipo_id', OLD.incibe_tipo_id, NEW.incibe_tipo_id, NEW.justificacion_categoria);
    END IF;

    IF (OLD.alerta_original_id IS DISTINCT FROM NEW.alerta_original_id) THEN
        INSERT INTO historial_cambios_alertas (alerta_id, usuario, campo_modificado, valor_anterior, valor_nuevo)
        VALUES (NEW.alerta_id, usuario_act, 'alerta_original_id', OLD.alerta_original_id::text, NEW.alerta_original_id::text);
    END IF;

    IF (OLD.es_sospechosa IS DISTINCT FROM NEW.es_sospechosa) THEN
        INSERT INTO historial_cambios_alertas (alerta_id, usuario, campo_modificado, valor_anterior, valor_nuevo, justificacion_cambio)
        VALUES (NEW.alerta_id, usuario_act, 'es_sospechosa', OLD.es_sospechosa::text, NEW.es_sospechosa::text, NEW.motivo_sospecha);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_auditoria_alerta ON alertas;
CREATE TRIGGER trigger_auditoria_alerta
    AFTER UPDATE ON alertas
    FOR EACH ROW EXECUTE FUNCTION trg_auditar_cambios_alerta();

-- La bandeja de entrada es la prueba: no se modifica ni se borra
CREATE OR REPLACE FUNCTION trg_bandeja_inmutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'bandeja_entrada es inmutable (prueba de qué llegó y cuándo)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_bandeja_inmutable ON bandeja_entrada;
CREATE TRIGGER trigger_bandeja_inmutable
    BEFORE UPDATE OR DELETE ON bandeja_entrada
    FOR EACH ROW EXECUTE FUNCTION trg_bandeja_inmutable();

-- ----------------------------------------------------------------------------
-- 9. EXTRACCIÓN DE CAMPOS (mejor esfuerzo, ajustar cuando veamos más formatos)
-- ----------------------------------------------------------------------------
-- Texto plano a partir de un cuerpo que puede venir en HTML
CREATE OR REPLACE FUNCTION texto_plano(p_texto TEXT)
RETURNS TEXT AS $$
    SELECT regexp_replace(
               replace(replace(replace(
                   regexp_replace(regexp_replace(coalesce(p_texto, ''), '<(br|/p|/div|/tr)[^>]*>', E'\n', 'gi'),
                                  '<[^>]+>', ' ', 'g'),
                   '&nbsp;', ' '), '&lt;', '<'), '&gt;', '>'),
               '[ \t]+', ' ', 'g')
$$ LANGUAGE sql IMMUTABLE;

-- Valor de la primera línea "Etiqueta: valor" cuya etiqueta coincida
CREATE OR REPLACE FUNCTION extraer_campo(p_texto TEXT, p_etiquetas TEXT)
RETURNS TEXT AS $$
    SELECT nullif(btrim(substring(p_texto FROM '(?i)(?:^|\n)\s*[*-]?\s*(?:' || p_etiquetas || ')\s*[:=]\s*([^\n]+)')), '')
$$ LANGUAGE sql IMMUTABLE;

-- Detección de correos que intentan manipular a una IA (se marcan, nunca se obedecen)
CREATE OR REPLACE FUNCTION motivo_sospecha_ia(p_asunto TEXT, p_cuerpo TEXT)
RETURNS TEXT AS $$
DECLARE
    t TEXT := lower(coalesce(p_asunto, '') || ' ' || coalesce(p_cuerpo, ''));
BEGIN
    IF t ~ '(ignora|ignore|olvida|disregard|omite).{0,40}(instrucci|instruction|anterior|previous|regla)' THEN
        RETURN 'Pide ignorar instrucciones previas';
    ELSIF t ~ '(si eres|if you are|como|as an?) (una |un )?(ia|ai|asistente|assistant|modelo de lenguaje|language model|llm)' THEN
        RETURN 'Texto dirigido a una IA';
    ELSIF t ~ '(chatgpt|claude|gemini|copilot|system prompt)' THEN
        RETURN 'Menciona herramientas de IA o prompts';
    ELSIF t ~ '(clasifica|marca|categoriza|classify|mark).{0,40}(como|as) (falso positivo|false positive|no_soc|informativ|benign|leg[ií]tim)' THEN
        RETURN 'Intenta imponer su propia clasificación';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ----------------------------------------------------------------------------
-- 10. PROCESADO DE CORREOS: bandeja_entrada -> alertas | correos_malformados
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_procesar_correo_entrante()
RETURNS TRIGGER AS $$
DECLARE
    v_texto        TEXT := texto_plano(NEW.cuerpo_correo_raw);
    v_sospecha     TEXT := motivo_sospecha_ia(NEW.asunto_correo, v_texto);
    v_prioridad    prioridad_soc_enum;
    v_peligrosidad peligrosidad_soc_enum;
    v_titulo       TEXT;
    v_equipo       TEXT;
    v_usuario      TEXT;
    v_fuente       TEXT;
    v_ip_txt       TEXT;
    v_ip           INET;
    v_fecha_raw    TEXT;
    v_fecha_evento TIMESTAMPTZ;
    v_zona         TEXT;
    v_hash         VARCHAR(64);
    v_original     UUID;
BEGIN
    -- Nomenclatura esperada: [SOC][Px][PELIGROSIDAD] Título
    IF NEW.asunto_correo !~* '^\s*\[SOC\]\s*\[P[1-4]\]\s*\[(INFORMATIVO|BAJO|MEDIO|ALTO|CR[IÍ]TICO)\]' THEN
        INSERT INTO correos_malformados (
            correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, motivo_descarte, es_sospechoso, motivo_sospecha
        ) VALUES (
            NEW.correo_id, NEW.id_mensaje_correo, NEW.remitente_correo, NEW.asunto_correo,
            NEW.cuerpo_correo_raw, NEW.fecha_hora_correo,
            'El asunto no sigue la nomenclatura requerida: [SOC][Px][PELIGROSIDAD]',
            v_sospecha IS NOT NULL, v_sospecha
        );
        RETURN NULL;
    END IF;

    BEGIN
        v_prioridad    := upper(substring(NEW.asunto_correo FROM '(?i)\[(P[1-4])\]'))::prioridad_soc_enum;
        v_peligrosidad := translate(upper(substring(NEW.asunto_correo
                              FROM '(?i)\[(INFORMATIVO|BAJO|MEDIO|ALTO|CR[IÍ]TICO)\]')), 'Í', 'I')::peligrosidad_soc_enum;
        v_titulo := btrim(regexp_replace(NEW.asunto_correo, '^\s*(\[[^]]*\]\s*){3}', ''));

        -- Campos del cuerpo
        v_equipo  := extraer_campo(v_texto, 'host|hostname|equipo|equipo afectado|servidor|dispositivo|device|m[aá]quina|endpoint');
        v_usuario := extraer_campo(v_texto, 'usuario|usuario afectado|user|username|cuenta|account');
        v_fuente  := left(extraer_campo(v_texto, 'fuente|herramienta|source|tool|sensor|producto|origen de la alerta'), 100);
        v_ip_txt  := coalesce(
            substring(extraer_campo(v_texto, 'ip|ip origen|ip afectada|ip de origen|direcci[oó]n ip|source ip|src_ip|ip address')
                      FROM '([0-9a-fA-F:.]{3,45})'),
            substring(v_texto FROM '\m((?:\d{1,3}\.){3}\d{1,3})\M'));
        BEGIN
            v_ip := v_ip_txt::inet;
        EXCEPTION WHEN others THEN
            v_ip := NULL;
        END;

        v_fecha_raw := left(extraer_campo(v_texto, 'fecha|fecha y hora|fecha/hora|timestamp|hora|time|date|detectado'), 100);
        BEGIN
            v_fecha_evento := v_fecha_raw::timestamptz;
            v_zona := CASE WHEN v_fecha_evento IS NULL THEN NULL
                           WHEN v_fecha_raw ~* '(z|utc|gmt|[+-]\d{2}:?\d{2}|cet|cest)\s*$' THEN
                               substring(v_fecha_raw FROM '(?i)(z|utc|gmt|[+-]\d{2}:?\d{2}|cet|cest)\s*$')
                           ELSE 'SIN_ZONA (interpretada como UTC)' END;
        EXCEPTION WHEN others THEN
            v_fecha_evento := NULL;
        END;

        -- Duplicado: mismo título + equipo + IP + usuario en una ventana de 24 h.
        -- Si no hay equipo/IP/usuario, se usa también el cuerpo para no fusionar alertas distintas.
        v_hash := encode(sha256(convert_to(lower(concat_ws('|',
                      v_titulo, v_equipo, v_ip::text, v_usuario,
                      CASE WHEN v_equipo IS NULL AND v_ip IS NULL AND v_usuario IS NULL
                           THEN regexp_replace(v_texto, '\s+', ' ', 'g') END)), 'UTF8')), 'hex');

        SELECT alerta_id INTO v_original
        FROM alertas
        WHERE hash_contenido = v_hash
          AND NOT es_duplicada
          AND fecha_hora_correo BETWEEN NEW.fecha_hora_correo - INTERVAL '24 hours'
                                    AND NEW.fecha_hora_correo + INTERVAL '24 hours'
        ORDER BY fecha_hora_correo
        LIMIT 1;

        INSERT INTO alertas (
            correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, soc_prioridad, soc_peligrosidad,
            titulo, descripcion, fuente_herramienta, equipo_afectado, ip_afectada, usuario_implicado,
            fecha_hora_evento, fecha_evento_raw, zona_horaria_original,
            hash_contenido, alerta_original_id, es_duplicada,
            es_sospechosa, motivo_sospecha, estado
        ) VALUES (
            NEW.correo_id, NEW.id_mensaje_correo, NEW.remitente_correo, NEW.asunto_correo,
            NEW.cuerpo_correo_raw, NEW.fecha_hora_correo, v_prioridad, v_peligrosidad,
            v_titulo, left(btrim(v_texto), 4000), v_fuente, v_equipo, v_ip, v_usuario,
            v_fecha_evento, v_fecha_raw, v_zona,
            v_hash, v_original, v_original IS NOT NULL,
            v_sospecha IS NOT NULL, v_sospecha,
            CASE WHEN v_sospecha IS NOT NULL THEN 'EN_REVISION'::estado_alerta_enum ELSE 'NUEVA' END
        );
    EXCEPTION WHEN others THEN
        -- Nunca se pierde un correo: si algo falla al procesarlo, queda para revisión manual
        INSERT INTO correos_malformados (
            correo_id, id_mensaje_correo, remitente_correo, asunto_correo,
            cuerpo_correo_raw, fecha_hora_correo, motivo_descarte, es_sospechoso, motivo_sospecha
        ) VALUES (
            NEW.correo_id, NEW.id_mensaje_correo, NEW.remitente_correo, NEW.asunto_correo,
            NEW.cuerpo_correo_raw, NEW.fecha_hora_correo,
            'Error al procesar: ' || SQLERRM, v_sospecha IS NOT NULL, v_sospecha
        );
    END;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Calcula la huella del correo original antes de guardarlo
CREATE OR REPLACE FUNCTION trg_hash_bandeja()
RETURNS TRIGGER AS $$
BEGIN
    NEW.hash_correo := encode(sha256(convert_to(concat_ws('|',
        NEW.id_mensaje_correo, NEW.remitente_correo, NEW.asunto_correo,
        NEW.cuerpo_correo_raw, NEW.fecha_hora_correo::text), 'UTF8')), 'hex');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_hash_bandeja ON bandeja_entrada;
CREATE TRIGGER trigger_hash_bandeja
    BEFORE INSERT ON bandeja_entrada
    FOR EACH ROW EXECUTE FUNCTION trg_hash_bandeja();

DROP TRIGGER IF EXISTS trigger_procesar_correo ON bandeja_entrada;
CREATE TRIGGER trigger_procesar_correo
    AFTER INSERT ON bandeja_entrada
    FOR EACH ROW EXECUTE FUNCTION trg_procesar_correo_entrante();

-- ----------------------------------------------------------------------------
-- 11. FUNCIÓN DE INGESTA (misma firma que el script original + parámetros opcionales)
--     Devuelve dónde ha acabado el correo. Re-enviar el mismo mensaje no da error.
-- ----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS registrar_correo_entrante(VARCHAR, VARCHAR, VARCHAR, TEXT, TIMESTAMP WITH TIME ZONE);

CREATE OR REPLACE FUNCTION registrar_correo_entrante(
    p_id_mensaje    VARCHAR(255),
    p_remitente     VARCHAR(255),
    p_asunto        VARCHAR(500),
    p_cuerpo        TEXT,
    p_fecha_hora    TIMESTAMP WITH TIME ZONE,
    p_destinatarios TEXT DEFAULT NULL,
    p_cabeceras     JSONB DEFAULT NULL,
    p_adjuntos      JSONB DEFAULT NULL,
    p_canal         VARCHAR(30) DEFAULT 'FUNCION_SQL'
)
RETURNS JSONB AS $$
DECLARE
    v_correo_id UUID;
    v_alerta    alertas%ROWTYPE;
    v_descarte  UUID;
BEGIN
    INSERT INTO bandeja_entrada (
        id_mensaje_correo, remitente_correo, destinatarios, asunto_correo,
        cuerpo_correo_raw, cabeceras, adjuntos, fecha_hora_correo, canal
    ) VALUES (
        p_id_mensaje, p_remitente, p_destinatarios, coalesce(p_asunto, ''),
        coalesce(p_cuerpo, ''), p_cabeceras, p_adjuntos, p_fecha_hora, p_canal
    )
    ON CONFLICT (id_mensaje_correo) DO NOTHING
    RETURNING correo_id INTO v_correo_id;

    IF v_correo_id IS NULL THEN
        RETURN jsonb_build_object('resultado', 'YA_REGISTRADO', 'id_mensaje', p_id_mensaje);
    END IF;

    SELECT * INTO v_alerta FROM alertas WHERE correo_id = v_correo_id;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'resultado', CASE WHEN v_alerta.es_duplicada THEN 'DUPLICADA' ELSE 'ALERTA' END,
            'alerta_id', v_alerta.alerta_id,
            'alerta_original_id', v_alerta.alerta_original_id,
            'sospechosa', v_alerta.es_sospechosa);
    END IF;

    SELECT descarte_id INTO v_descarte FROM correos_malformados WHERE correo_id = v_correo_id;
    RETURN jsonb_build_object('resultado', 'MALFORMADO', 'descarte_id', v_descarte);
END;
$$ LANGUAGE plpgsql;
