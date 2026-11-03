-- ============================================================================
-- pruebas.sql — Datos de prueba de "Insercion de datos" en un esquema aparte.
-- No toca las tablas reales (public): sirve para montar el dashboard sin correos.
-- Se puede re-ejecutar: borra y recrea SOLO el esquema "pruebas".
-- Uso: db/psql.sh -f db/seed/pruebas.sql
-- Cambios respecto al original: clases/tipos INCIBE oficiales e impacto según la guía
-- (MUY_BAJO -> SIN_IMPACTO).
-- ============================================================================

DROP SCHEMA IF EXISTS pruebas CASCADE;
CREATE SCHEMA pruebas;

CREATE TABLE pruebas.alertas             (LIKE public.alertas INCLUDING ALL);
CREATE TABLE pruebas.correos_malformados (LIKE public.correos_malformados INCLUDING ALL);

INSERT INTO pruebas.alertas (
    id_mensaje_correo, remitente_correo, asunto_correo, cuerpo_correo_raw, fecha_hora_correo,
    soc_prioridad, soc_peligrosidad, titulo, incibe_clase_id, incibe_tipo_id, justificacion_categoria,
    metodo_categorizacion, impacto_incibe, estado, hash_contenido, revisado_por_humano
) VALUES
-- Caso 1: P1 / CRITICO / IA / MUY_ALTO / NUEVA
('<MSG-001@soc.es>', 'soc-hackaton', '[SOC][P1][CRÍTICO] Infección por Ransomware detectada',
 'Se detectó cifrado masivo de archivos en servidor principal.', '2026-11-03 13:00:00+01',
 'P1', 'CRITICO', 'Infección por Ransomware detectada', 'CONTENIDO_DANINO', 'SISTEMA_INFECTADO',
 'Detección por comportamiento heurístico.', 'IA', 'MUY_ALTO', 'NUEVA', md5('MSG-001'), FALSE),
-- Caso 2: P2 / ALTO / REGLAS / ALTO / EN_REVISION
('<MSG-002@soc.es>', 'soc-hackaton', '[SOC][P2][ALTO] Ráfaga de accesos fallidos en Active Directory',
 'Múltiples intentos de inicio de sesión en menos de 1 minuto.', '2026-11-03 13:30:00+01',
 'P2', 'ALTO', 'Ráfaga de accesos fallidos en Active Directory', 'INTENTO_INTRUSION', 'INTENTO_ACCESO_CREDENCIALES',
 'Regla SIEM disparada por umbral de intentos.', 'REGLAS', 'ALTO', 'EN_REVISION', md5('MSG-002'), TRUE),
-- Caso 3: P3 / MEDIO / HIBRIDO / MEDIO / CONFIRMADA
('<MSG-003@soc.es>', 'soc-hackaton', '[SOC][P3][MEDIO] Fuga potencial de información por USB',
 'Copia de volumen inusual de archivos confidenciales a dispositivo externo.', '2026-11-03 12:15:00+01',
 'P3', 'MEDIO', 'Fuga potencial de información por USB', 'COMPROMISO_INFORMACION', 'ACCESO_NO_AUTORIZADO',
 'Filtro DLP + modelo predictivo de IA.', 'HIBRIDO', 'MEDIO', 'CONFIRMADA', md5('MSG-003'), TRUE),
-- Caso 4: P4 / BAJO / HUMANO / BAJO / FALSA_ALARMA
('<MSG-004@soc.es>', 'soc-hackaton', '[SOC][P4][BAJO] Comportamiento anómalo en equipo local',
 'Escaneo de puertos interno detectado.', '2026-11-03 13:23:00+01',
 'P4', 'BAJO', 'Comportamiento anómalo en equipo local', 'OBTENCION_INFORMACION', 'ESCANEO_REDES',
 'Tráfico verificado por el analista: tarea programada legítima.', 'HUMANO', 'BAJO', 'FALSA_ALARMA', md5('MSG-004'), TRUE),
-- Caso 5: P4 / INFORMATIVO / REGLAS / SIN_IMPACTO / NO_SOC
('<MSG-005@soc.es>', 'soc-hackaton', '[SOC][P4][INFORMATIVO] Liberación por mantenimiento programado',
 'Aviso automático del sistema de ticketing sobre tareas de infraestructura.', '2026-11-03 13:36:00+01',
 'P4', 'INFORMATIVO', 'Liberación por mantenimiento programado', 'OTROS', 'OTROS',
 'Correo informativo que no constituye una amenaza.', 'REGLAS', 'SIN_IMPACTO', 'NO_SOC', md5('MSG-005'), FALSE),
-- Caso 6: P1 / CRITICO / HUMANO / ALTO / CERRADA
('<MSG-006@soc.es>', 'soc-hackaton', '[SOC][P1][CRÍTICO] Ataque DDoS sobre el portal público',
 'Saturación de tráfico HTTP/S mitigada con éxito.', '2026-11-03 10:00:00+01',
 'P1', 'CRITICO', 'Ataque DDoS sobre el portal público', 'DISPONIBILIDAD', 'DDOS',
 'Incidente resuelto y cerrado por el equipo SOC.', 'HUMANO', 'ALTO', 'CERRADA', md5('MSG-006'), TRUE);

INSERT INTO pruebas.correos_malformados (
    id_mensaje_correo, remitente_correo, asunto_correo, cuerpo_correo_raw, fecha_hora_correo,
    motivo_descarte, estado
) VALUES
('<MSG-MAL-001@soc.es>', 'soc-hackaton', 'SOC: Posible correo sospechoso',
 'No cumple la nomenclatura [SOC][Px][PELIGROSIDAD]', '2026-11-03 11:02:00+01',
 'Falta la etiqueta de prioridad y peligrosidad en el asunto.', 'PENDIENTE_REVISION'),
('<MSG-MAL-002@soc.es>', 'externo@gmail.com', 'Consulta sobre presupuesto de seguridad',
 'Correo de ventas entrante al buzón de alertas.', '2026-11-03 09:15:00+01',
 'El asunto no sigue la nomenclatura requerida.', 'DESCARTADO'),
('<MSG-MAL-003@soc.es>', 'analista@empresa.com', 'Re: Fwd: Alerta manual detectada',
 'Correo reenviado manualmente por un empleado.', '2026-11-03 08:30:00+01',
 'Nomenclatura no estándar. Convertido en alerta UUID manualmente.', 'PROCESADO_MANUALMENTE');
