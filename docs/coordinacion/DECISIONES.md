# Registro de decisiones — Equipo 2

Formato: ID · fecha/hora · decisión · motivo · quién decide · estado.

## D-001 · 03/11/2026 · PostgreSQL de Azure como única fuente de verdad
- **Decisión:** todos los datos (correos, alertas, clasificaciones, auditoría y bloqueos) viven en la PostgreSQL de Azure.
  La web deja de leer del almacenamiento de Sites y pasa a leer de PostgreSQL mediante rutas de API del servidor, que solo consultan las vistas `v_*`.
- **Motivo:** el enunciado fija la PostgreSQL del equipo como la base de datos del reto. Una sola fuente evita cifras distintas entre la web y la BD.
  Además, las revisiones y los bloqueos hechos desde la web hoy no llegan a PostgreSQL.
- **Transición:** la sincronización Sites → PostgreSQL (GitHub Actions) se mantiene hasta que Power Automate inserte directamente en `bandeja_entrada`.
- **Decide:** responsable de BD. **Estado:** aprobada, pendiente de implementar.

## D-002 · 03/11/2026 · Ramas y Pull Requests
- **Decisión:** nadie hace push a `main`. Ramas `bd/...` y `web/...`; merge por PR con la revisión de la otra parte.
- **Motivo:** dos IAs y varias personas sobre el mismo repo; así se evitan conflictos y queda la traza.
- **Decide:** equipo. **Estado:** propuesta, pendiente de que Pau la confirme.

## D-003 · 03/11/2026 · Bloqueo automático de nivel 2
- **Decisión:** ante una alerta crítica muy clara, el sistema bloquea solo la IP y/o el usuario. El bloqueo es permanente hasta que una persona lo libera, y la liberación se hace con un clic.
- **Filtros, en orden:** no duplicada, no sospechosa, **no es una petición por correo** (nadie puede pedir bloqueos por email), estado válido, remitente de confianza, sin inconsistencias, IP pública (las internas pueden ser el servidor afectado), fuera de la lista blanca, posterior a la última liberación manual y número mínimo de alertas en la ventana de la regla.
- **Además:** si el objetivo ya está bloqueado, no se repite el bloqueo. Cada decisión, también los descartes, queda justificada en `decisiones_bloqueo_auto`.
- **Seguridad:** el ejecutor arranca en simulación (`BLOQUEO_AUTO_ACTIVO=0`) y no reintenta automáticamente.
- **Decide:** equipo, tras el feedback de los jefes del proyecto. **Estado:** implementada (migración 005), pendiente de aplicar en Azure.

## D-004 · 03/11/2026 · Análisis por horas, periodos y contexto geopolítico
- **Decisión:** mapa de calor día × hora, carga y coste por franja horaria (una hora de guardia no cuesta lo mismo que una laboral), estadísticas por semana, mes y año exportables, y cruce de los picos con eventos geopolíticos ligados a estados.
- **Pendiente:** el coste por hora de cada franja y los minutos por alerta los facilitará Administración. Hasta entonces, `coste_manual_eur` queda vacío.
- **Datos simulados:** permitidos para enseñar las vistas mensual y anual, siempre etiquetados como simulados.
- **Decide:** equipo, tras el feedback de los jefes. **Estado:** implementada (migración 006), pendiente de aplicar en Azure.
