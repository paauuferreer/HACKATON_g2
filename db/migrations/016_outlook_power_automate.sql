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
