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
