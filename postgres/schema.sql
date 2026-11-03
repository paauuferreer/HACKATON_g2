-- Esquema de referencia aislado. Revisar con el responsable de base de datos.
-- No modifica tablas existentes de otros esquemas.
CREATE SCHEMA IF NOT EXISTS hackapol_soc;
SET search_path TO hackapol_soc;
CREATE TABLE IF NOT EXISTS incidents (
 id text PRIMARY KEY, source_key text NOT NULL UNIQUE, subject text NOT NULL,
 sender text NOT NULL, received_at text NOT NULL, body text NOT NULL,
 analysis text NOT NULL CHECK (jsonb_typeof(analysis::jsonb)='object'),
 status text NOT NULL DEFAULT 'Nueva', evidence_key text NOT NULL,
 evidence_hash text NOT NULL, created_at text NOT NULL,
 duplicate_of text REFERENCES incidents(id), group_key text,
 revision integer NOT NULL DEFAULT 0, updated_at text
);
CREATE INDEX IF NOT EXISTS incidents_received ON incidents(received_at);
CREATE INDEX IF NOT EXISTS incidents_group ON incidents(group_key);
CREATE TABLE IF NOT EXISTS alert_groups (key text PRIMARY KEY, incident_id text NOT NULL);
CREATE TABLE IF NOT EXISTS operations (
 id text PRIMARY KEY, incident_id text NOT NULL REFERENCES incidents(id),
 action text NOT NULL, type text NOT NULL, value text NOT NULL, actor text NOT NULL,
 reason text NOT NULL, state text NOT NULL, created_at text NOT NULL,
 response text, http_status integer,
 UNIQUE(incident_id,type,value,action)
);
CREATE TABLE IF NOT EXISTS target_locks (
 key text PRIMARY KEY, operation_id text NOT NULL, created_at text NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id text PRIMARY KEY,actor text NOT NULL,event text NOT NULL,detail text NOT NULL,
 created_at text NOT NULL
);
-- Las fechas se guardan en ISO-8601 UTC para compartir el contrato con Sites.
-- analysis mantiene campos de extracción + clase INCIBE + versión + explicación.
-- Las credenciales de ejecución solo necesitan SELECT/INSERT/UPDATE en estas tablas,
-- DELETE en target_locks. La migración se ejecuta con un rol distinto.
