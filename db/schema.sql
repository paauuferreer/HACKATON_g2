-- schema.sql — esquema consolidado de referencia (= db/migrations en orden). Aplicar con: .venv/bin/python db/migrate.py
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
-- ============================================================================
-- 002_vistas_dashboard.sql — Vistas para el cuadro de mando (el frontend no lleva lógica)
-- Todas excluyen las alertas duplicadas (es_duplicada = FALSE).
-- ============================================================================

CREATE OR REPLACE VIEW v_incibe_taxonomia AS
SELECT c.clase_id, c.nombre AS clase, t.tipo_id, t.nombre AS tipo, c.orden
FROM incibe_clases c
LEFT JOIN incibe_tipos t ON t.clase_id = c.clase_id
ORDER BY c.orden, t.nombre;

CREATE OR REPLACE VIEW v_alertas AS
SELECT a.alerta_id,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AS fecha,
       a.fecha_hora_evento, a.fecha_hora_correo,
       a.soc_prioridad, a.soc_peligrosidad,
       a.titulo, a.asunto_correo, a.remitente_correo,
       a.fuente_herramienta, a.equipo_afectado, a.ip_afectada, a.usuario_implicado,
       a.incibe_clase_id, c.nombre AS clase_incibe, a.incibe_tipo_id, t.nombre AS tipo_incibe,
       a.justificacion_categoria, a.metodo_categorizacion, a.impacto_incibe, a.peligrosidad_incibe,
       a.estado, a.es_sospechosa, a.motivo_sospecha,
       a.revisado_por_humano, a.usuario_analista,
       (SELECT count(*) FROM alertas d WHERE d.alerta_original_id = a.alerta_id) AS num_duplicados,
       a.correo_id, a.id_mensaje_correo
FROM alertas a
LEFT JOIN incibe_clases c ON c.clase_id = a.incibe_clase_id
LEFT JOIN incibe_tipos  t ON t.tipo_id  = a.incibe_tipo_id
WHERE NOT a.es_duplicada;

CREATE OR REPLACE VIEW v_stats_clase AS
SELECT coalesce(clase_incibe, 'Sin clasificar') AS clase, incibe_clase_id, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_prioridad_peligrosidad AS
SELECT soc_prioridad, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_fuente AS
SELECT coalesce(fuente_herramienta, 'Desconocida') AS fuente, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_estado AS
SELECT estado, count(*) AS total
FROM v_alertas
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_equipos AS
SELECT lower(equipo_afectado) AS equipo, count(*) AS total, max(fecha) AS ultima,
       max(soc_peligrosidad) AS peligrosidad_max,
       array_agg(DISTINCT clase_incibe) FILTER (WHERE clase_incibe IS NOT NULL) AS clases
FROM v_alertas
WHERE equipo_afectado IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_usuarios AS
SELECT lower(usuario_implicado) AS usuario, count(*) AS total, max(fecha) AS ultima,
       max(soc_peligrosidad) AS peligrosidad_max,
       array_agg(DISTINCT clase_incibe) FILTER (WHERE clase_incibe IS NOT NULL) AS clases
FROM v_alertas
WHERE usuario_implicado IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_top_ips AS
SELECT ip_afectada AS ip, count(*) AS total, max(fecha) AS ultima,
       array_agg(DISTINCT lower(equipo_afectado)) FILTER (WHERE equipo_afectado IS NOT NULL) AS equipos
FROM v_alertas
WHERE ip_afectada IS NOT NULL AND estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1;

CREATE OR REPLACE VIEW v_timeline AS
SELECT date_trunc('hour', fecha) AS hora, coalesce(clase_incibe, 'Sin clasificar') AS clase, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

-- KPIs para la cabecera del dashboard y el análisis de ROI (incluye ruido y duplicados)
CREATE OR REPLACE VIEW v_kpis AS
SELECT (SELECT count(*) FROM bandeja_entrada)                                   AS correos_recibidos,
       (SELECT count(*) FROM alertas)                                           AS alertas_total,
       (SELECT count(*) FROM alertas WHERE es_duplicada)                        AS duplicadas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada)                    AS alertas_unicas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado = 'FALSA_ALARMA') AS falsas_alarmas,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado = 'NO_SOC')       AS no_soc,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND estado IN ('NUEVA','EN_REVISION')) AS pendientes,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND soc_prioridad = 'P1')    AS p1,
       (SELECT count(*) FROM alertas WHERE NOT es_duplicada AND incibe_clase_id IS NULL) AS sin_clasificar,
       (SELECT count(*) FROM alertas WHERE es_sospechosa)
         + (SELECT count(*) FROM correos_malformados WHERE es_sospechoso)       AS sospechosos,
       (SELECT count(*) FROM correos_malformados)                               AS malformados,
       (SELECT count(*) FROM correos_malformados WHERE estado = 'PENDIENTE_REVISION') AS malformados_pendientes,
       (SELECT count(*) FROM acciones_bloqueo WHERE accion = 'BLOQUEAR' AND exito)     AS bloqueos_ok;
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
-- ============================================================================
-- 004_vistas_formato_real.sql — Vistas con los campos del formato real (sede, IDs, inconsistencias)
-- CREATE OR REPLACE VIEW solo permite añadir columnas al final.
-- ============================================================================

CREATE OR REPLACE VIEW v_alertas AS
SELECT a.alerta_id,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AS fecha,
       a.fecha_hora_evento, a.fecha_hora_correo,
       a.soc_prioridad, a.soc_peligrosidad,
       a.titulo, a.asunto_correo, a.remitente_correo,
       a.fuente_herramienta, a.equipo_afectado, a.ip_afectada, a.usuario_implicado,
       a.incibe_clase_id, c.nombre AS clase_incibe, a.incibe_tipo_id, t.nombre AS tipo_incibe,
       a.justificacion_categoria, a.metodo_categorizacion, a.impacto_incibe, a.peligrosidad_incibe,
       a.estado, a.es_sospechosa, a.motivo_sospecha,
       a.revisado_por_humano, a.usuario_analista,
       (SELECT count(*) FROM alertas d WHERE d.alerta_original_id = a.alerta_id) AS num_duplicados,
       a.correo_id, a.id_mensaje_correo,
       -- añadidas en 004
       a.sede, a.regla_deteccion, a.criticidad_cuerpo, a.ip_raw,
       a.id_alerta_soc, a.referencia_soc, a.id_solicitud,
       a.fecha_ultimo_evento, a.fecha_emision,
       a.inconsistencias, a.regla_id, a.remitente_confianza
FROM alertas a
LEFT JOIN incibe_clases c ON c.clase_id = a.incibe_clase_id
LEFT JOIN incibe_tipos  t ON t.tipo_id  = a.incibe_tipo_id
WHERE NOT a.es_duplicada;

CREATE OR REPLACE VIEW v_stats_sede AS
SELECT coalesce(sede, 'Sin sede') AS sede, soc_peligrosidad, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

CREATE OR REPLACE VIEW v_stats_tipo AS
SELECT coalesce(clase_incibe, 'Sin clasificar') AS clase, coalesce(tipo_incibe, '—') AS tipo, count(*) AS total
FROM v_alertas
WHERE estado NOT IN ('NO_SOC', 'FALSA_ALARMA')
GROUP BY 1, 2;

-- Alertas que el analista debería mirar dos veces (trampas del buzón)
CREATE OR REPLACE VIEW v_inconsistencias AS
SELECT alerta_id, fecha, referencia_soc, titulo, soc_prioridad, soc_peligrosidad, criticidad_cuerpo,
       unnest(inconsistencias) AS inconsistencia
FROM v_alertas
WHERE cardinality(inconsistencias) > 0
UNION ALL
SELECT alerta_id, fecha, referencia_soc, titulo, soc_prioridad, soc_peligrosidad, criticidad_cuerpo,
       'Sospechosa: ' || motivo_sospecha
FROM v_alertas
WHERE es_sospechosa;

-- Solicitudes de bloqueo / liberación pendientes de decidir (alimentan la automatización con la API)
CREATE OR REPLACE VIEW v_solicitudes AS
SELECT alerta_id, fecha_hora_correo, id_solicitud, titulo, usuario_implicado, ip_afectada, estado,
       remitente_correo, remitente_confianza, es_sospechosa, motivo_sospecha
FROM v_alertas
WHERE id_solicitud IS NOT NULL
ORDER BY fecha_hora_correo;
