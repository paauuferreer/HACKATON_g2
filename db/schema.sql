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

-- ============================================================================
-- 006_analitica_temporal.sql — Análisis por horas, franjas, semanas, meses, años y contexto geopolítico
--
-- Todas las horas se expresan en Europe/Madrid (hora de la empresa).
-- Columnas comunes de las vistas:
--   total   = alertas únicas (sin duplicados): mide CARGA de trabajo, el ruido también cuesta revisarlo
--   reales  = sin FALSA_ALARMA ni NO_SOC: mide AMENAZA
--   criticas, p1 = alertas únicas con peligrosidad CRITICO / prioridad P1
-- Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. FRANJAS HORARIAS Y PARÁMETROS DE NEGOCIO (los costes los rellena Administración)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS franjas_horarias (
    franja        VARCHAR(30) PRIMARY KEY,
    descripcion   TEXT NOT NULL,
    orden         SMALLINT NOT NULL,
    coste_hora_eur NUMERIC(8, 2),               -- NULL hasta tener el dato real
    es_hipotesis  BOOLEAN NOT NULL DEFAULT TRUE,
    fuente        TEXT
);
INSERT INTO franjas_horarias (franja, descripcion, orden) VALUES
    ('LABORAL',               'Lunes a viernes laborables, 08:00-17:59', 1),
    ('GUARDIA_TARDE',         'Lunes a viernes laborables, 18:00-21:59', 2),
    ('FIN_DE_SEMANA_FESTIVO', 'Sábados, domingos y festivos, 08:00-21:59', 3),
    ('GUARDIA_NOCHE',         'Todos los días, 22:00-07:59', 4)
ON CONFLICT (franja) DO NOTHING;

CREATE TABLE IF NOT EXISTS festivos (
    fecha  DATE PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL
);

-- Valores para el ROI (clave → valor). Cada cifra indica si es hipótesis y de dónde sale.
CREATE TABLE IF NOT EXISTS parametros_negocio (
    clave        VARCHAR(50) PRIMARY KEY,
    valor        NUMERIC(12, 2),
    unidad       VARCHAR(30) NOT NULL,
    descripcion  TEXT NOT NULL,
    es_hipotesis BOOLEAN NOT NULL DEFAULT TRUE,
    fuente       TEXT
);
INSERT INTO parametros_negocio (clave, valor, unidad, descripcion) VALUES
    ('minutos_revision_manual', NULL, 'min/alerta', 'Tiempo medio que tarda hoy un analista en revisar una alerta a mano'),
    ('minutos_revision_sistema', NULL, 'min/alerta', 'Tiempo medio de revisión con nuestra solución')
ON CONFLICT (clave) DO NOTHING;

CREATE OR REPLACE FUNCTION franja_horaria(p_ts TIMESTAMP WITH TIME ZONE) RETURNS VARCHAR AS $$
DECLARE
    v_local TIMESTAMP := p_ts AT TIME ZONE 'Europe/Madrid';
    v_hora  INTEGER   := extract(hour FROM v_local);
BEGIN
    IF p_ts IS NULL THEN
        RETURN NULL;
    ELSIF v_hora >= 22 OR v_hora < 8 THEN
        RETURN 'GUARDIA_NOCHE';
    ELSIF extract(isodow FROM v_local) >= 6
          OR EXISTS (SELECT 1 FROM festivos WHERE fecha = v_local::date) THEN
        RETURN 'FIN_DE_SEMANA_FESTIVO';
    ELSIF v_hora >= 18 THEN
        RETURN 'GUARDIA_TARDE';
    ELSE
        RETURN 'LABORAL';
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- ----------------------------------------------------------------------------
-- 2. BASE COMÚN: una fila por alerta (incluye duplicadas para poder contarlas)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_alertas_tiempo AS
SELECT a.alerta_id,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo)                            AS fecha,
       coalesce(a.fecha_hora_evento, a.fecha_hora_correo) AT TIME ZONE 'Europe/Madrid' AS fecha_local,
       franja_horaria(coalesce(a.fecha_hora_evento, a.fecha_hora_correo))            AS franja,
       a.es_duplicada,
       NOT a.es_duplicada AND a.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')             AS es_real,
       a.estado, a.soc_prioridad, a.soc_peligrosidad, a.incibe_clase_id, a.es_sospechosa,
       a.fuente_herramienta, a.sede
FROM alertas a;

-- ----------------------------------------------------------------------------
-- 3. MAPA DE CALOR día de la semana × hora (Europe/Madrid)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_heatmap_dia_hora AS
SELECT d.dia_semana, d.nombre_dia, h.hora,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)                                   AS total,
       count(t.alerta_id) FILTER (WHERE t.es_real)                                            AS reales,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO') AS criticas,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_prioridad = 'P1')         AS p1
FROM (VALUES (1, 'Lunes'), (2, 'Martes'), (3, 'Miércoles'), (4, 'Jueves'),
             (5, 'Viernes'), (6, 'Sábado'), (7, 'Domingo')) d(dia_semana, nombre_dia)
CROSS JOIN generate_series(0, 23) h(hora)
LEFT JOIN v_alertas_tiempo t
       ON extract(isodow FROM t.fecha_local) = d.dia_semana
      AND extract(hour   FROM t.fecha_local) = h.hora
GROUP BY d.dia_semana, d.nombre_dia, h.hora;

-- ----------------------------------------------------------------------------
-- 4. CARGA Y COSTE POR FRANJA HORARIA (coste NULL hasta que Administración dé las cifras)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_stats_franja AS
SELECT f.orden, f.franja, f.descripcion, f.coste_hora_eur, f.es_hipotesis,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)                                    AS total,
       count(t.alerta_id) FILTER (WHERE t.es_real)                                             AS reales,
       count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO') AS criticas,
       count(t.alerta_id) FILTER (WHERE t.es_duplicada)                                        AS duplicadas,
       round(count(t.alerta_id) FILTER (WHERE NOT t.es_duplicada)
             * (SELECT valor FROM parametros_negocio WHERE clave = 'minutos_revision_manual') / 60.0
             * f.coste_hora_eur, 2)                                                            AS coste_manual_eur
FROM franjas_horarias f
LEFT JOIN v_alertas_tiempo t ON t.franja = f.franja
GROUP BY f.orden, f.franja, f.descripcion, f.coste_hora_eur, f.es_hipotesis;

-- ----------------------------------------------------------------------------
-- 5. ESTADÍSTICAS POR PERIODO: hora, día, semana, mes y año (exportables tal cual)
--    Filtrar por granularidad: WHERE granularidad = 'mes'
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_stats_periodo AS
WITH g(granularidad, unidad) AS (
    VALUES ('hora', 'hour'), ('dia', 'day'), ('semana', 'week'), ('mes', 'month'), ('anio', 'year'))
SELECT g.granularidad,
       date_trunc(g.unidad, t.fecha_local)                                                     AS periodo,
       count(*) FILTER (WHERE NOT t.es_duplicada)                                              AS total,
       count(*) FILTER (WHERE t.es_real)                                                       AS reales,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'CRITICO')           AS criticas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_peligrosidad = 'ALTO')              AS altas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.soc_prioridad = 'P1')                   AS p1,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.estado = 'FALSA_ALARMA')                AS falsas_alarmas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.estado = 'NO_SOC')                      AS no_soc,
       count(*) FILTER (WHERE t.es_sospechosa)                                                 AS sospechosas,
       count(*) FILTER (WHERE t.es_duplicada)                                                  AS duplicadas,
       count(*) FILTER (WHERE NOT t.es_duplicada AND t.franja <> 'LABORAL')                    AS fuera_horario
FROM v_alertas_tiempo t
CROSS JOIN g
GROUP BY g.granularidad, date_trunc(g.unidad, t.fecha_local);

-- ----------------------------------------------------------------------------
-- 6. CONTEXTO GEOPOLÍTICO: eventos externos para cruzar con los picos de alertas
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eventos_geopoliticos (
    evento_id    BIGSERIAL PRIMARY KEY,
    fecha_inicio DATE NOT NULL,
    fecha_fin    DATE,                     -- NULL = un solo día
    titulo       VARCHAR(200) NOT NULL,
    descripcion  TEXT,
    region       VARCHAR(100),
    actores      TEXT,                     -- p. ej. grupos APT o estados atribuidos
    fuente_url   TEXT,
    es_simulado  BOOLEAN NOT NULL DEFAULT FALSE,
    creado_por   VARCHAR(100) NOT NULL,
    fecha_alta   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_evento_fechas CHECK (fecha_fin IS NULL OR fecha_fin >= fecha_inicio)
);

-- Picos por hora: más del doble de la media de las 24 h anteriores (y al menos 3 alertas)
CREATE OR REPLACE VIEW v_picos_hora AS
WITH h AS (
    SELECT periodo AS hora, total, reales, criticas
    FROM v_stats_periodo WHERE granularidad = 'hora'
), m AS (
    SELECT h1.hora, h1.total, h1.reales, h1.criticas,
           (SELECT coalesce(sum(h2.total), 0) / 24.0 FROM h h2
            WHERE h2.hora >= h1.hora - interval '24 hours' AND h2.hora < h1.hora) AS media_24h
    FROM h h1
)
SELECT hora, total, reales, criticas, round(media_24h, 2) AS media_24h,
       total >= 3 AND total > 2 * media_24h AS es_pico
FROM m;

-- Día a día: alertas, media de los 7 días anteriores, pico y eventos geopolíticos activos ese día
CREATE OR REPLACE VIEW v_timeline_geopolitica AS
WITH d AS (
    SELECT periodo::date AS dia, total, reales, criticas
    FROM v_stats_periodo WHERE granularidad = 'dia'
), m AS (
    SELECT d1.*,
           (SELECT coalesce(sum(d2.total), 0) / 7.0 FROM d d2
            WHERE d2.dia >= d1.dia - 7 AND d2.dia < d1.dia) AS media_7d
    FROM d d1
)
SELECT m.dia, m.total, m.reales, m.criticas, round(m.media_7d, 2) AS media_7d,
       m.total >= 3 AND m.total > 2 * m.media_7d AS es_pico,
       count(e.evento_id) AS num_eventos,
       string_agg(e.titulo || CASE WHEN e.es_simulado THEN ' (simulado)' ELSE '' END, ' · '
                  ORDER BY e.fecha_inicio) AS eventos
FROM m
LEFT JOIN eventos_geopoliticos e
       ON m.dia BETWEEN e.fecha_inicio AND coalesce(e.fecha_fin, e.fecha_inicio)
GROUP BY m.dia, m.total, m.reales, m.criticas, m.media_7d;

-- ============================================================================
-- 007_texto_plano_html.sql — Extracción correcta de la tabla de campos de los correos HTML reales
--
-- Problema: los correos del SOC traen saltos de línea en el código HTML entre <td>etiqueta</td> y
-- <td>valor</td>. texto_plano() los conservaba, así que etiqueta y valor quedaban en líneas distintas
-- y extraer_campo() cogía la palabra siguiente (usuario "relacionada", equipo "de", sede/fuente vacías).
-- En HTML los espacios y saltos del código no significan nada: se colapsan antes de convertir las
-- etiquetas de bloque en saltos de línea. Los correos en texto plano no cambian.
--
-- Después se reprocesan las alertas ya guardadas, solo si ninguna ha sido tocada por una persona ni
-- ha generado acciones de bloqueo (la bandeja_entrada es la evidencia y no se modifica).
-- Idempotente.
-- ============================================================================

CREATE OR REPLACE FUNCTION texto_plano(p_texto TEXT)
RETURNS TEXT AS $$
    SELECT regexp_replace(regexp_replace(
               replace(replace(replace(replace(replace(
                   regexp_replace(regexp_replace(regexp_replace(regexp_replace(
                       CASE WHEN p_texto ~* '<(html|body|table|tr|td|p|div|br)\M'
                            THEN regexp_replace(p_texto, '\s+', ' ', 'g')
                            ELSE coalesce(p_texto, '') END,
                       '<(script|style)[^>]*>.*?</\1>', ' ', 'gi'),
                       '</(td|th)>', ' | ', 'gi'),
                       '<(br|/p|/div|/tr|/li|/h[1-6])[^>]*>', E'\n', 'gi'),
                       '<[^>]+>', ' ', 'g'),
                   '&nbsp;', ' '), '&lt;', '<'), '&gt;', '>'), '&amp;', '&'), '**', ''),
               '[ \t]+', ' ', 'g'),
           '\n\s*\n+', E'\n', 'g')
$$ LANGUAGE sql IMMUTABLE;

-- Borra y vuelve a generar las alertas desde la bandeja (tras corregir la extracción).
-- No hace nada si alguna alerta tiene revisión humana o acciones de bloqueo. Devuelve correos procesados.
CREATE OR REPLACE FUNCTION reprocesar_alertas() RETURNS INTEGER AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM alertas WHERE coalesce(revisado_por_humano, FALSE) OR usuario_analista IS NOT NULL)
       OR EXISTS (SELECT 1 FROM acciones_bloqueo WHERE alerta_id IS NOT NULL) THEN
        RAISE NOTICE 'Reproceso omitido: hay alertas revisadas por una persona o con acciones de bloqueo';
        RETURN 0;
    END IF;
    UPDATE correos_malformados SET alerta_convertida_id = NULL WHERE alerta_convertida_id IS NOT NULL;
    DELETE FROM alertas;          -- historial y decisiones caen en cascada
    RETURN procesar_pendientes();
END;
$$ LANGUAGE plpgsql;

SELECT reprocesar_alertas();

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

-- ============================================================================
-- 011_organizacion_outlook.sql — El buzón de Outlook se ordena según la base de datos (decisión D-008)
--
-- Petición: que la bandeja de entrada esté organizada con carpetas y etiquetas según el correo que llega.
-- Diseño:
--   * CARPETA  = qué hay que hacer con el correo (una por correo): directrices, SOC por urgencia,
--                solicitudes, ruido, cuarentena, no SOC.
--   * ETIQUETAS (categorías de Outlook, varias por correo) = qué es: gravedad, clase INCIBE y señales
--                (verificado, sospechoso, duplicado, inconsistente, bloqueo...).
--   * Lo decide SOLO la base de datos (misma clasificación que el cuadro de mando). El script
--     soc/outlook_organizar.py lo aplica con Microsoft Graph y registra cada cambio.
--   * Solo se mueven correos que ya están guardados en bandeja_entrada: el flujo de Power Automate
--     que se dispara en la Bandeja de entrada nunca pierde un correo.
-- Todo es configuración editable (nombres, colores, remitentes). Idempotente.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CONFIGURACIÓN
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS config_outlook (
    id                      SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    organizacion_activa     BOOLEAN NOT NULL DEFAULT TRUE,       -- interruptor general desde la BD
    remitentes_directrices  TEXT[]  NOT NULL DEFAULT '{dirti@sampol.com}',
    remitentes_soc          TEXT[]  NOT NULL DEFAULT '{soc-hackaton@sampol.com}',
    fecha_actualizacion     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO config_outlook (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Carpetas: ruta relativa a la Bandeja de entrada ("/" separa subcarpetas)
CREATE TABLE IF NOT EXISTS outlook_carpetas (
    codigo      VARCHAR(30) PRIMARY KEY,
    ruta        VARCHAR(200) NOT NULL UNIQUE,
    descripcion TEXT NOT NULL,
    orden       SMALLINT NOT NULL
);
INSERT INTO outlook_carpetas (codigo, ruta, descripcion, orden) VALUES
    ('DIRECTRICES',  '01 Directrices',             'Correos del director de TI', 1),
    ('SOC_CRITICAS', '02 SOC/Críticas y altas',    'Alertas del SOC críticas o altas pendientes de acción', 2),
    ('SOC_MEDIAS',   '02 SOC/Medias y bajas',      'Alertas del SOC de gravedad media o baja', 3),
    ('SOC_REVISION', '02 SOC/Revisión manual',     'Correos del SOC que el sistema no pudo interpretar', 4),
    ('SOC_CERRADAS', '02 SOC/Cerradas',            'Alertas del SOC cerradas', 5),
    ('SOLICITUDES',  '03 Solicitudes (SOL)',       'Peticiones de bloqueo o liberación: nunca se ejecutan solas', 6),
    ('RUIDO',        '04 Ruido',                   'Duplicados, informativos y falsas alarmas', 7),
    ('CUARENTENA',   '05 Cuarentena',              'Correos sospechosos, manipulados o con autenticidad fallida', 8),
    ('NO_SOC',       '06 No SOC',                  'Organización, avisos de servicios y otros', 9)
ON CONFLICT (codigo) DO NOTHING;

-- Etiquetas (categorías de Outlook). color = preset de Microsoft Graph (preset0 rojo ... preset24)
CREATE TABLE IF NOT EXISTS outlook_categorias (
    grupo   VARCHAR(10) NOT NULL CHECK (grupo IN ('GRAVEDAD', 'INCIBE', 'SENAL')),
    clave   VARCHAR(50) NOT NULL,
    nombre  VARCHAR(60) NOT NULL UNIQUE,
    color   VARCHAR(10) NOT NULL CHECK (color ~ '^preset([0-9]|1[0-9]|2[0-4])$'),
    orden   SMALLINT NOT NULL,
    PRIMARY KEY (grupo, clave)
);
INSERT INTO outlook_categorias (grupo, clave, nombre, color, orden) VALUES
    ('GRAVEDAD', 'CRITICO',     'Gravedad: Crítica',     'preset0',  1),
    ('GRAVEDAD', 'ALTO',        'Gravedad: Alta',        'preset1',  2),
    ('GRAVEDAD', 'MEDIO',       'Gravedad: Media',       'preset3',  3),
    ('GRAVEDAD', 'BAJO',        'Gravedad: Baja',        'preset4',  4),
    ('GRAVEDAD', 'INFORMATIVO', 'Gravedad: Informativa', 'preset12', 5),
    ('SENAL', 'DIRECTRIZ',         'Directriz',                 'preset10', 30),
    ('SENAL', 'VERIFICADO',        'Remitente verificado',      'preset19', 31),
    ('SENAL', 'NO_VERIFICADO',     'Remitente sin verificar',   'preset13', 32),
    ('SENAL', 'SOSPECHOSO',        'Sospechoso',                'preset15', 33),
    ('SENAL', 'EXTERNO',           'Remitente externo',         'preset11', 34),
    ('SENAL', 'INCONSISTENTE',     'Inconsistente',             'preset2',  35),
    ('SENAL', 'DUPLICADO',         'Duplicado',                 'preset13', 36),
    ('SENAL', 'SOLICITUD',         'Solicitud: no ejecutar',    'preset17', 37),
    ('SENAL', 'FALSA_ALARMA',      'Falsa alarma',              'preset12', 38),
    ('SENAL', 'REVISION',          'Pendiente de revisión',     'preset18', 39),
    ('SENAL', 'BLOQUEO_PENDIENTE', 'Bloqueo en curso',          'preset16', 40),
    ('SENAL', 'BLOQUEO',           'Bloqueo aplicado',          'preset20', 41),
    ('SENAL', 'RECOMENDACION',     'Recomendación de bloqueo',  'preset21', 42),
    ('SENAL', 'NO_SOC',            'No SOC',                    'preset14', 43)
ON CONFLICT (grupo, clave) DO NOTHING;

-- Una etiqueta por clase INCIBE, con el nombre del catálogo
INSERT INTO outlook_categorias (grupo, clave, nombre, color, orden)
SELECT 'INCIBE', c.clase_id, left('INCIBE: ' || c.nombre, 60), v.color, 10 + coalesce(c.orden, 0)
FROM incibe_clases c
JOIN (VALUES ('CONTENIDO_ABUSIVO', 'preset9'), ('CONTENIDO_DANINO', 'preset24'), ('OBTENCION_INFORMACION', 'preset5'),
             ('INTENTO_INTRUSION', 'preset7'), ('INTRUSION', 'preset22'), ('DISPONIBILIDAD', 'preset6'),
             ('COMPROMISO_INFORMACION', 'preset23'), ('FRAUDE', 'preset8'), ('VULNERABLE', 'preset21'),
             ('OTROS', 'preset12')) AS v(clase_id, color) ON v.clase_id = c.clase_id
ON CONFLICT (grupo, clave) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. REGISTRO DE LO APLICADO EN OUTLOOK (auditoría y control de cambios)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outlook_sincronizacion (
    correo_id        UUID PRIMARY KEY REFERENCES bandeja_entrada(correo_id),
    carpeta_codigo   VARCHAR(30) REFERENCES outlook_carpetas(codigo),
    categorias       TEXT[] NOT NULL DEFAULT '{}',
    huella           VARCHAR(32) NOT NULL,            -- md5(carpeta + etiquetas): detecta cambios
    graph_message_id TEXT,
    estado           VARCHAR(15) NOT NULL CHECK (estado IN ('APLICADO', 'NO_ENCONTRADO', 'ERROR')),
    detalle          TEXT,
    intentos         INTEGER NOT NULL DEFAULT 1,
    fecha            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outlook_sinc_estado ON outlook_sincronizacion (estado, fecha);

CREATE OR REPLACE FUNCTION registrar_sincronizacion_outlook(
    p_correo_id UUID, p_huella TEXT, p_carpeta TEXT, p_categorias TEXT[],
    p_graph_id TEXT, p_estado TEXT, p_detalle TEXT)
RETURNS VOID AS $$
    INSERT INTO outlook_sincronizacion
        (correo_id, carpeta_codigo, categorias, huella, graph_message_id, estado, detalle, intentos, fecha)
    VALUES (p_correo_id, p_carpeta, coalesce(p_categorias, '{}'), p_huella, p_graph_id, p_estado, left(p_detalle, 1000), 1, now())
    ON CONFLICT (correo_id) DO UPDATE SET
        carpeta_codigo   = EXCLUDED.carpeta_codigo,
        categorias       = EXCLUDED.categorias,
        graph_message_id = coalesce(EXCLUDED.graph_message_id, outlook_sincronizacion.graph_message_id),
        estado           = EXCLUDED.estado,
        detalle          = EXCLUDED.detalle,
        intentos         = CASE WHEN outlook_sincronizacion.huella = EXCLUDED.huella AND EXCLUDED.estado <> 'APLICADO'
                                THEN outlook_sincronizacion.intentos + 1 ELSE 1 END,
        huella           = EXCLUDED.huella,
        fecha            = now();
$$ LANGUAGE sql;

-- ----------------------------------------------------------------------------
-- 3. DESTINO DE CADA CORREO
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_outlook_destino AS
WITH cfg AS (SELECT * FROM config_outlook WHERE id = 1),
base AS (
    SELECT b.correo_id, b.fecha_hora_correo, lower(btrim(b.remitente_correo)) AS remitente,
           b.asunto_correo,
           -- Identificador para encontrar el correo en Outlook (InternetMessageId completo si lo guardó la ingesta)
           coalesce(nullif(b.cabeceras ->> 'original_message_id', ''), b.id_mensaje_correo) AS id_outlook,
           a.alerta_id, a.referencia_soc, a.id_alerta_soc, a.soc_peligrosidad, a.criticidad_cuerpo,
           a.incibe_clase_id, a.estado::text AS estado_alerta, a.es_duplicada, a.id_solicitud,
           coalesce(cardinality(a.inconsistencias), 0) AS num_inconsistencias,
           m.descarte_id,
           -- procesar_correo() marca como sospechoso a todo remitente fuera de remitentes_confianza; para ordenar
           -- el buzón solo cuentan los motivos reales (instrucciones a una IA, clasificación impuesta...)
           nullif(btrim(regexp_replace(coalesce(a.motivo_sospecha, m.motivo_sospecha, ''),
                                       'Remitente fuera de la lista de confianza \([^)]*\)', '', 'g'), '; '), '') AS sospecha_real,
           coalesce(au.verificada, FALSE) AS verificada, au.motivo AS motivo_autenticidad,
           -- Un EML sin ninguna cabecera Received no ha pasado por un servidor de correo: inyectado o manipulado
           (b.eml_raw IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM cabeceras_eml(b.correo_id) h WHERE h.nombre = 'received')) AS sin_transporte,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_directrices) x) AS es_director,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_soc) x) AS es_soc
    FROM bandeja_entrada b
    LEFT JOIN alertas a ON a.correo_id = b.correo_id
    LEFT JOIN correos_malformados m ON m.correo_id = b.correo_id AND a.alerta_id IS NULL
    LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE
),
clasif AS (
    SELECT base.*,
           sospecha_real IS NOT NULL AS marcado_sospechoso,
           alerta_id IS NOT NULL AND NOT es_soc AND NOT es_director AS formato_soc_suplantado,
           CASE WHEN verificada THEN 'VERIFICADO'
                WHEN motivo_autenticidad LIKE 'Remitente externo%' THEN 'EXTERNO'
                WHEN motivo_autenticidad LIKE 'Sin %' OR motivo_autenticidad LIKE 'Falta %'
                     OR motivo_autenticidad LIKE 'Correo interno sin%' THEN 'SIN_DATOS'
                ELSE 'FALLIDA' END AS autenticidad,
           alerta_id IS NOT NULL AND (
               id_solicitud IS NOT NULL
               OR asunto_correo ~* '\mSOL-[0-9]+'
               OR plegar(asunto_correo) ~ 'solicitud (de )?(bloqueo|liberacion|desbloqueo)') AS es_solicitud,
           plegar(soc_peligrosidad::text) IN ('critico', 'alto')
               OR plegar(criticidad_cuerpo) ~ '^(critic|alt)' AS es_grave,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND ba.confirmado) AS bloqueo_confirmado,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND NOT ba.confirmado) AS bloqueo_en_curso,
           EXISTS (SELECT 1 FROM decisiones_bloqueo_auto d WHERE d.alerta_id = base.alerta_id AND d.decision = 'RECOMENDAR') AS recomendado
    FROM base
),
destino AS (
    SELECT clasif.*,
           CASE
               WHEN alerta_id IS NULL AND descarte_id IS NULL THEN NULL           -- aún sin procesar: se queda en la Bandeja
               WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte THEN 'CUARENTENA'
               WHEN es_director THEN 'DIRECTRICES'
               WHEN formato_soc_suplantado THEN 'CUARENTENA'
               WHEN autenticidad = 'EXTERNO' THEN 'NO_SOC'
               WHEN descarte_id IS NOT NULL AND es_soc THEN 'SOC_REVISION'
               WHEN descarte_id IS NOT NULL THEN 'NO_SOC'
               WHEN es_solicitud THEN 'SOLICITUDES'
               WHEN es_duplicada OR estado_alerta = 'FALSA_ALARMA' OR soc_peligrosidad::text = 'INFORMATIVO' THEN 'RUIDO'
               WHEN estado_alerta = 'NO_SOC' THEN 'NO_SOC'
               WHEN estado_alerta = 'CERRADA' THEN 'SOC_CERRADAS'
               WHEN es_grave THEN 'SOC_CRITICAS'
               ELSE 'SOC_MEDIAS'
           END AS carpeta_codigo,
           array_remove(ARRAY[
               CASE WHEN soc_peligrosidad IS NOT NULL THEN 'GRAVEDAD:' || soc_peligrosidad::text END,
               CASE WHEN incibe_clase_id IS NOT NULL THEN 'INCIBE:' || incibe_clase_id END,
               CASE WHEN es_director THEN 'SENAL:DIRECTRIZ' END,
               CASE WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte OR formato_soc_suplantado THEN 'SENAL:SOSPECHOSO'
                    WHEN autenticidad = 'VERIFICADO' THEN 'SENAL:VERIFICADO'
                    WHEN autenticidad = 'EXTERNO' THEN 'SENAL:EXTERNO'
                    ELSE 'SENAL:NO_VERIFICADO' END,
               CASE WHEN num_inconsistencias > 0 THEN 'SENAL:INCONSISTENTE' END,
               CASE WHEN es_duplicada THEN 'SENAL:DUPLICADO' END,
               CASE WHEN es_solicitud THEN 'SENAL:SOLICITUD' END,
               CASE WHEN estado_alerta = 'FALSA_ALARMA' THEN 'SENAL:FALSA_ALARMA' END,
               CASE WHEN (descarte_id IS NOT NULL AND es_soc) OR estado_alerta = 'EN_REVISION' THEN 'SENAL:REVISION' END,
               CASE WHEN bloqueo_confirmado THEN 'SENAL:BLOQUEO'
                    WHEN bloqueo_en_curso THEN 'SENAL:BLOQUEO_PENDIENTE'
                    WHEN recomendado THEN 'SENAL:RECOMENDACION' END,
               CASE WHEN (descarte_id IS NOT NULL AND NOT es_soc AND NOT es_director) OR estado_alerta = 'NO_SOC'
                         OR autenticidad = 'EXTERNO' THEN 'SENAL:NO_SOC' END
           ], NULL) AS claves
    FROM clasif
)
SELECT d.correo_id, d.fecha_hora_correo, d.remitente, d.id_outlook, d.alerta_id,
       coalesce(d.referencia_soc, d.id_alerta_soc) AS referencia,
       d.carpeta_codigo, c.ruta AS carpeta_ruta,
       coalesce((SELECT array_agg(oc.nombre ORDER BY oc.orden)
                 FROM outlook_categorias oc
                 WHERE oc.grupo || ':' || oc.clave = ANY (d.claves)), '{}') AS categorias,
       CASE d.carpeta_codigo
           WHEN 'CUARENTENA'   THEN 'Sospechoso: ' || coalesce(d.sospecha_real,
                                                               CASE WHEN d.sin_transporte THEN 'sin cabeceras de transporte (posible inyección)' END,
                                                               CASE WHEN d.autenticidad = 'FALLIDA' THEN d.motivo_autenticidad END,
                                                               CASE WHEN d.formato_soc_suplantado THEN 'formato de alerta SOC enviado por ' || d.remitente || ', que no es el SOC' END,
                                                               'marcado por las reglas de detección')
           WHEN 'DIRECTRICES'  THEN 'Remitente de directrices (' || d.autenticidad || ')'
           WHEN 'NO_SOC'       THEN 'No es una alerta del SOC (' || d.autenticidad || ')'
           WHEN 'SOC_REVISION' THEN 'Correo del SOC sin formato reconocible: revisión manual'
           WHEN 'SOLICITUDES'  THEN 'Petición de bloqueo o liberación: no se ejecuta desde el correo'
           WHEN 'RUIDO'        THEN CASE WHEN d.es_duplicada THEN 'Duplicado de otra alerta'
                                         WHEN d.estado_alerta = 'FALSA_ALARMA' THEN 'Falsa alarma'
                                         ELSE 'Alerta informativa' END
           WHEN 'SOC_CERRADAS' THEN 'Alerta cerrada'
           WHEN 'SOC_CRITICAS' THEN 'Alerta crítica o alta pendiente'
           WHEN 'SOC_MEDIAS'   THEN 'Alerta media o baja'
       END AS motivo,
       md5(coalesce(d.carpeta_codigo, '') || '|' || array_to_string(ARRAY(SELECT x FROM unnest(d.claves) x ORDER BY x), ',')) AS huella
FROM destino d
LEFT JOIN outlook_carpetas c ON c.codigo = d.carpeta_codigo;

-- Lo que el script tiene que aplicar: correos nuevos, con cambios, o con errores que toca reintentar
CREATE OR REPLACE VIEW v_outlook_pendientes AS
SELECT d.*
FROM v_outlook_destino d
LEFT JOIN outlook_sincronizacion s ON s.correo_id = d.correo_id
WHERE d.carpeta_codigo IS NOT NULL
  AND (s.correo_id IS NULL
       OR s.huella <> d.huella
       OR (s.estado <> 'APLICADO' AND s.intentos < 6 AND s.fecha < now() - interval '10 minutes'))
ORDER BY d.fecha_hora_correo;

-- Resumen por carpeta (dashboard y comprobaciones)
CREATE OR REPLACE VIEW v_outlook_resumen AS
SELECT c.orden, c.codigo, c.ruta,
       count(d.correo_id)                                       AS correos,
       count(s.correo_id) FILTER (WHERE s.estado = 'APLICADO' AND s.huella = d.huella) AS aplicados,
       count(d.correo_id) FILTER (WHERE s.correo_id IS NULL OR s.huella <> d.huella OR s.estado <> 'APLICADO') AS pendientes
FROM outlook_carpetas c
LEFT JOIN v_outlook_destino d ON d.carpeta_codigo = c.codigo
LEFT JOIN outlook_sincronizacion s ON s.correo_id = d.correo_id
GROUP BY c.orden, c.codigo, c.ruta;

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

-- ============================================================================
-- 013_auto06_correlacion.sql — Regla AUTO-06: bloqueo temprano por correlación de fases (D-009)
--
-- En la cadena *moreno, la cuenta se ve comprometida ~40 min ANTES de la primera alerta crítica
-- (phishing → ráfaga de fallos → acceso correcto que el titular no reconoce → … → mando y control).
-- AUTO-05 solo actúa con la crítica: llega tarde. AUTO-06 bloquea la cuenta en cuanto aparece la fase
-- COMPROMISO precedida, en la ventana, de al menos una fase previa (phishing o fuerza bruta) sobre el
-- mismo usuario. Fases: tabla fases_ataque (012).
-- Mismos filtros de seguridad que AUTO-05 (duplicado, sospechoso, petición SOL, estado, remitente SOC
-- autenticado, inconsistencias, cuenta del dominio, lista blanca, liberación humana, cuenta protegida).
-- Aquí la prueba es la secuencia de fases, no la gravedad: se ignoran las discrepancias asunto/cuerpo.
-- AUTO-06 vive en reglas_bloqueo_auto con peligrosidades vacías: evaluar_bloqueo_auto() nunca la elige;
-- la evalúa solo evaluar_cadena_compromiso(). Idempotente; no reevalúa nada al aplicarse.
-- ============================================================================

ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS fase_disparadora  VARCHAR(30) REFERENCES fases_ataque(fase);
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS fases_previas     TEXT[];
ALTER TABLE reglas_bloqueo_auto ADD COLUMN IF NOT EXISTS min_fases_previas INTEGER NOT NULL DEFAULT 1;

INSERT INTO reglas_bloqueo_auto
    (regla_id, descripcion, objetivo, prioridades, peligrosidades, clases_incibe,
     requiere_remitente_confianza, excluir_inconsistentes, solo_ip_publica, min_alertas, ventana_minutos, orden,
     antiguedad_max_minutos, inconsistencias_ignoradas, inconsistencias_solo_ip, ip_automatica, requiere_autenticacion,
     fase_disparadora, fases_previas, min_fases_previas)
VALUES
    ('AUTO-06', 'Correlación: cuenta comprometida (acceso no reconocido) precedida de phishing o fuerza bruta sobre el mismo usuario en 2 h',
     'USUARIO', '{P1,P2,P3,P4}', '{}', NULL,
     TRUE, TRUE, TRUE, 1, 120, 6,
     NULL, '{"Prioridad % incoherente con gravedad %","Gravedad del asunto % distinta de la criticidad del cuerpo %"}',
     '{"Dirección relacionada con formato no válido%"}', FALSE, TRUE,
     'COMPROMISO', '{ACCESO_INICIAL,CREDENCIALES}', 1)
ON CONFLICT (regla_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- EVALUACIÓN. Se llama con cualquier alerta: si es de una fase previa, reevalúa el compromiso posterior
-- del mismo usuario (los correos pueden llegar desordenados). Devuelve acciones creadas.
-- ----------------------------------------------------------------------------
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

    -- Fases previas distintas del mismo usuario en la ventana (alertas fiables)
    SELECT coalesce(array_agg(DISTINCT f), '{}') INTO v_previas
    FROM (SELECT fase_de_titulo(p.titulo) AS f
          FROM alertas p
          WHERE NOT p.es_duplicada AND NOT p.es_sospechosa
            AND p.estado NOT IN ('FALSA_ALARMA', 'NO_SOC')
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
        v_motivo := format('Acceso no reconocido sin phishing ni fuerza bruta previos en %s min: no hay cadena; lo valora una persona',
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

-- Histórico: evalúa los compromisos de las últimas p_horas (por hora del evento)
CREATE OR REPLACE FUNCTION evaluar_cadena_pendientes(p_horas INTEGER DEFAULT 24) RETURNS INTEGER AS $$
DECLARE
    v_id    UUID;
    v_total INTEGER := 0;
BEGIN
    FOR v_id IN
        SELECT a.alerta_id FROM alertas a
        WHERE NOT a.es_duplicada
          AND fase_de_titulo(a.titulo) = (SELECT fase_disparadora FROM reglas_bloqueo_auto WHERE regla_id = 'AUTO-06')
          AND coalesce(a.fecha_hora_evento, a.fecha_hora_correo) >= now() - make_interval(hours => p_horas)
        ORDER BY coalesce(a.fecha_hora_evento, a.fecha_hora_correo)
    LOOP
        v_total := v_total + evaluar_cadena_compromiso(v_id);
    END LOOP;
    RETURN v_total;
END;
$$ LANGUAGE plpgsql;

-- Trigger: evaluación inmediata al crear cualquier alerta (nunca rompe la ingesta)
CREATE OR REPLACE FUNCTION trg_cadena_compromiso() RETURNS TRIGGER AS $$
BEGIN
    BEGIN
        PERFORM evaluar_cadena_compromiso(NEW.alerta_id);
    EXCEPTION WHEN others THEN
        RAISE WARNING 'AUTO-06 no evaluada para la alerta %: %', NEW.alerta_id, SQLERRM;
    END;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_cadena_compromiso ON alertas;
CREATE TRIGGER trigger_cadena_compromiso
    AFTER INSERT ON alertas
    FOR EACH ROW
    WHEN (NOT NEW.es_duplicada)
    EXECUTE FUNCTION trg_cadena_compromiso();

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

-- ============================================================================
-- 015_outlook_aviso_ia_externo.sql — Avisos externos que solo mencionan una herramienta de IA → «06 No SOC»
--
-- Despliegue de BD-011: el aviso de inicio de sesión de noreply@tm.openai.com caía en «05 Cuarentena» por
-- "Menciona herramientas de IA o prompts" (nombra ChatGPT), cuando lo esperado es «06 No SOC».
-- Se relaja SOLO ese motivo, y solo si el remitente es externo, el correo tiene cabeceras de transporte, no
-- es una alerta del SOC y no intenta imponer una clasificación. "Pide ignorar instrucciones" y "Texto
-- dirigido a una IA" siguen yendo a cuarentena siempre. Misma vista que la 011 (mismas columnas). Idempotente.
-- ============================================================================

CREATE OR REPLACE VIEW v_outlook_destino AS
WITH cfg AS (SELECT * FROM config_outlook WHERE id = 1),
base AS (
    SELECT b.correo_id, b.fecha_hora_correo, lower(btrim(b.remitente_correo)) AS remitente,
           b.asunto_correo,
           -- Identificador para encontrar el correo en Outlook (InternetMessageId completo si lo guardó la ingesta)
           coalesce(nullif(b.cabeceras ->> 'original_message_id', ''), b.id_mensaje_correo) AS id_outlook,
           a.alerta_id, a.referencia_soc, a.id_alerta_soc, a.soc_peligrosidad, a.criticidad_cuerpo,
           a.incibe_clase_id, a.estado::text AS estado_alerta, a.es_duplicada, a.id_solicitud,
           coalesce(cardinality(a.inconsistencias), 0) AS num_inconsistencias,
           m.descarte_id,
           -- procesar_correo() marca como sospechoso a todo remitente fuera de remitentes_confianza; para ordenar
           -- el buzón solo cuentan los motivos reales (instrucciones a una IA, clasificación impuesta...)
           nullif(btrim(regexp_replace(coalesce(a.motivo_sospecha, m.motivo_sospecha, ''),
                                       'Remitente fuera de la lista de confianza \([^)]*\)', '', 'g'), '; '), '') AS sospecha_real,
           coalesce(au.verificada, FALSE) AS verificada, au.motivo AS motivo_autenticidad,
           -- Un EML sin ninguna cabecera Received no ha pasado por un servidor de correo: inyectado o manipulado
           (b.eml_raw IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM cabeceras_eml(b.correo_id) h WHERE h.nombre = 'received')) AS sin_transporte,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_directrices) x) AS es_director,
           lower(btrim(b.remitente_correo)) = ANY (SELECT lower(x) FROM cfg, unnest(cfg.remitentes_soc) x) AS es_soc,
           -- motivo_sospecha_ia() solo devuelve el primer motivo y mira "menciona IA" antes que "impone clasificación":
           -- se vuelve a comprobar aquí para no relajar un correo que haga las dos cosas (015)
           lower(coalesce(b.asunto_correo, '') || ' ' || texto_plano(b.cuerpo_correo_raw))
               ~ '(clasifica|marca|categoriza|classify|mark).{0,40}(como|as) (falso positivo|false positive|no_soc|informativ|benign|leg[ií]tim)'
               AS impone_clasificacion
    FROM bandeja_entrada b
    LEFT JOIN alertas a ON a.correo_id = b.correo_id
    LEFT JOIN correos_malformados m ON m.correo_id = b.correo_id AND a.alerta_id IS NULL
    LEFT JOIN LATERAL autenticidad_correo(b.correo_id) au ON TRUE
),
clasif AS (
    SELECT base.*,
           -- Un aviso externo que solo nombra una herramienta de IA (p. ej. el inicio de sesión de OpenAI) no es
           -- sospechoso: pasó por servidores de correo, no imita una alerta del SOC y no da órdenes (015)
           sospecha_real IS NOT NULL
               AND NOT (sospecha_real = 'Menciona herramientas de IA o prompts'
                        AND motivo_autenticidad LIKE 'Remitente externo%'
                        AND NOT sin_transporte
                        AND alerta_id IS NULL
                        AND NOT impone_clasificacion) AS marcado_sospechoso,
           alerta_id IS NOT NULL AND NOT es_soc AND NOT es_director AS formato_soc_suplantado,
           CASE WHEN verificada THEN 'VERIFICADO'
                WHEN motivo_autenticidad LIKE 'Remitente externo%' THEN 'EXTERNO'
                WHEN motivo_autenticidad LIKE 'Sin %' OR motivo_autenticidad LIKE 'Falta %'
                     OR motivo_autenticidad LIKE 'Correo interno sin%' THEN 'SIN_DATOS'
                ELSE 'FALLIDA' END AS autenticidad,
           alerta_id IS NOT NULL AND (
               id_solicitud IS NOT NULL
               OR asunto_correo ~* '\mSOL-[0-9]+'
               OR plegar(asunto_correo) ~ 'solicitud (de )?(bloqueo|liberacion|desbloqueo)') AS es_solicitud,
           plegar(soc_peligrosidad::text) IN ('critico', 'alto')
               OR plegar(criticidad_cuerpo) ~ '^(critic|alt)' AS es_grave,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND ba.confirmado) AS bloqueo_confirmado,
           EXISTS (SELECT 1 FROM v_bloqueos_activos ba WHERE ba.alerta_id = base.alerta_id AND NOT ba.confirmado) AS bloqueo_en_curso,
           EXISTS (SELECT 1 FROM decisiones_bloqueo_auto d WHERE d.alerta_id = base.alerta_id AND d.decision = 'RECOMENDAR') AS recomendado
    FROM base
),
destino AS (
    SELECT clasif.*,
           CASE
               WHEN alerta_id IS NULL AND descarte_id IS NULL THEN NULL           -- aún sin procesar: se queda en la Bandeja
               WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte THEN 'CUARENTENA'
               WHEN es_director THEN 'DIRECTRICES'
               WHEN formato_soc_suplantado THEN 'CUARENTENA'
               WHEN autenticidad = 'EXTERNO' THEN 'NO_SOC'
               WHEN descarte_id IS NOT NULL AND es_soc THEN 'SOC_REVISION'
               WHEN descarte_id IS NOT NULL THEN 'NO_SOC'
               WHEN es_solicitud THEN 'SOLICITUDES'
               WHEN es_duplicada OR estado_alerta = 'FALSA_ALARMA' OR soc_peligrosidad::text = 'INFORMATIVO' THEN 'RUIDO'
               WHEN estado_alerta = 'NO_SOC' THEN 'NO_SOC'
               WHEN estado_alerta = 'CERRADA' THEN 'SOC_CERRADAS'
               WHEN es_grave THEN 'SOC_CRITICAS'
               ELSE 'SOC_MEDIAS'
           END AS carpeta_codigo,
           array_remove(ARRAY[
               CASE WHEN soc_peligrosidad IS NOT NULL THEN 'GRAVEDAD:' || soc_peligrosidad::text END,
               CASE WHEN incibe_clase_id IS NOT NULL THEN 'INCIBE:' || incibe_clase_id END,
               CASE WHEN es_director THEN 'SENAL:DIRECTRIZ' END,
               CASE WHEN marcado_sospechoso OR autenticidad = 'FALLIDA' OR sin_transporte OR formato_soc_suplantado THEN 'SENAL:SOSPECHOSO'
                    WHEN autenticidad = 'VERIFICADO' THEN 'SENAL:VERIFICADO'
                    WHEN autenticidad = 'EXTERNO' THEN 'SENAL:EXTERNO'
                    ELSE 'SENAL:NO_VERIFICADO' END,
               CASE WHEN num_inconsistencias > 0 THEN 'SENAL:INCONSISTENTE' END,
               CASE WHEN es_duplicada THEN 'SENAL:DUPLICADO' END,
               CASE WHEN es_solicitud THEN 'SENAL:SOLICITUD' END,
               CASE WHEN estado_alerta = 'FALSA_ALARMA' THEN 'SENAL:FALSA_ALARMA' END,
               CASE WHEN (descarte_id IS NOT NULL AND es_soc) OR estado_alerta = 'EN_REVISION' THEN 'SENAL:REVISION' END,
               CASE WHEN bloqueo_confirmado THEN 'SENAL:BLOQUEO'
                    WHEN bloqueo_en_curso THEN 'SENAL:BLOQUEO_PENDIENTE'
                    WHEN recomendado THEN 'SENAL:RECOMENDACION' END,
               CASE WHEN (descarte_id IS NOT NULL AND NOT es_soc AND NOT es_director) OR estado_alerta = 'NO_SOC'
                         OR autenticidad = 'EXTERNO' THEN 'SENAL:NO_SOC' END
           ], NULL) AS claves
    FROM clasif
)
SELECT d.correo_id, d.fecha_hora_correo, d.remitente, d.id_outlook, d.alerta_id,
       coalesce(d.referencia_soc, d.id_alerta_soc) AS referencia,
       d.carpeta_codigo, c.ruta AS carpeta_ruta,
       coalesce((SELECT array_agg(oc.nombre ORDER BY oc.orden)
                 FROM outlook_categorias oc
                 WHERE oc.grupo || ':' || oc.clave = ANY (d.claves)), '{}') AS categorias,
       CASE d.carpeta_codigo
           WHEN 'CUARENTENA'   THEN 'Sospechoso: ' || coalesce(d.sospecha_real,
                                                               CASE WHEN d.sin_transporte THEN 'sin cabeceras de transporte (posible inyección)' END,
                                                               CASE WHEN d.autenticidad = 'FALLIDA' THEN d.motivo_autenticidad END,
                                                               CASE WHEN d.formato_soc_suplantado THEN 'formato de alerta SOC enviado por ' || d.remitente || ', que no es el SOC' END,
                                                               'marcado por las reglas de detección')
           WHEN 'DIRECTRICES'  THEN 'Remitente de directrices (' || d.autenticidad || ')'
           WHEN 'NO_SOC'       THEN 'No es una alerta del SOC (' || d.autenticidad || ')'
           WHEN 'SOC_REVISION' THEN 'Correo del SOC sin formato reconocible: revisión manual'
           WHEN 'SOLICITUDES'  THEN 'Petición de bloqueo o liberación: no se ejecuta desde el correo'
           WHEN 'RUIDO'        THEN CASE WHEN d.es_duplicada THEN 'Duplicado de otra alerta'
                                         WHEN d.estado_alerta = 'FALSA_ALARMA' THEN 'Falsa alarma'
                                         ELSE 'Alerta informativa' END
           WHEN 'SOC_CERRADAS' THEN 'Alerta cerrada'
           WHEN 'SOC_CRITICAS' THEN 'Alerta crítica o alta pendiente'
           WHEN 'SOC_MEDIAS'   THEN 'Alerta media o baja'
       END AS motivo,
       md5(coalesce(d.carpeta_codigo, '') || '|' || array_to_string(ARRAY(SELECT x FROM unnest(d.claves) x ORDER BY x), ',')) AS huella
FROM destino d
LEFT JOIN outlook_carpetas c ON c.codigo = d.carpeta_codigo;

-- ============================================================================
-- 016_outlook_power_automate.sql — Plan B de BD-011: Power Automate ordena el buzón (sin Client ID de Graph)
--
-- El inicio de sesión del script soc/outlook_organizar.py (device code) no se pudo completar. Power Automate
-- ya tiene una conexión de Outlook con el propio buzón: un flujo programado lee la cola, mueve cada correo
-- a su carpeta y devuelve el resultado. La BD sigue decidiendo (v_outlook_destino, 011/015).
-- Para no depender de cómo convierte el conector arrays, UUID o upserts:
--   * v_outlook_pendientes_pa: la cola de v_outlook_pendientes con todo en texto y las etiquetas en JSON.
--   * outlook_resultados_pa: Power Automate solo INSERTA aquí (columnas de texto); el trigger registra el
--     resultado con registrar_sincronizacion_outlook() (011), igual que el script.
-- Guía del flujo: docs/POWER-AUTOMATE-OUTLOOK.md. Idempotente.
-- ============================================================================

CREATE OR REPLACE VIEW v_outlook_pendientes_pa AS
SELECT p.correo_id::text            AS correo_id,
       p.id_outlook,
       p.carpeta_codigo,
       p.carpeta_ruta,
       to_json(p.categorias)::text  AS categorias_json,
       p.huella,
       p.fecha_hora_correo
FROM v_outlook_pendientes p
-- Mismo interruptor general que el script: con organizacion_activa = FALSE la cola sale vacía
WHERE coalesce((SELECT c.organizacion_activa FROM config_outlook c WHERE c.id = 1), TRUE);

CREATE TABLE IF NOT EXISTS outlook_resultados_pa (
    resultado_id     BIGSERIAL PRIMARY KEY,
    correo_id        TEXT NOT NULL,
    huella           VARCHAR(32) NOT NULL,
    carpeta_codigo   VARCHAR(30),
    graph_message_id TEXT,
    estado           VARCHAR(15) NOT NULL CHECK (estado IN ('APLICADO', 'NO_ENCONTRADO', 'ERROR')),
    detalle          TEXT,
    fecha            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION trg_outlook_resultado_pa() RETURNS TRIGGER AS $$
DECLARE
    v_id UUID;
BEGIN
    v_id := NEW.correo_id::uuid;   -- un correo_id mal formado hace fallar la inserción: el flujo lo verá
    PERFORM registrar_sincronizacion_outlook(
        v_id, NEW.huella, NEW.carpeta_codigo,
        (SELECT d.categorias::text[] FROM v_outlook_destino d WHERE d.correo_id = v_id),
        NEW.graph_message_id, NEW.estado, coalesce(NEW.detalle, 'Power Automate'));
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_outlook_resultado_pa ON outlook_resultados_pa;
CREATE TRIGGER trigger_outlook_resultado_pa
    AFTER INSERT ON outlook_resultados_pa
    FOR EACH ROW
    EXECUTE FUNCTION trg_outlook_resultado_pa();

