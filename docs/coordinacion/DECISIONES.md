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

## D-005 · 03/11/2026 · Bloqueo automático alineado con el ejecutor seguro (WEB-004)
- **Decisión:** se adopta el ejecutor seguro de web (`soc/run-automation.mjs`), con estos criterios:
  - **Usuarios sí; IPs nunca de forma automática**, porque pueden ser servidores públicos. Las IPs quedan como `RECOMENDAR`, a un clic.
  - **Solo alertas recientes** (15 min). Las antiguas generan recomendaciones, nunca bloqueos.
  - **Regla AUTO-04 de doble confirmación** para el formato real `[P4][CRÍTICO]`: asunto y cuerpo deben ser críticos.
- **Motivo:** une la petición del responsable de BD (bloquear usuarios y también IPs, con filtros) y la de Pau (no bloquear servidores). Además corrige el fallo del primer ejecutor: hacía el POST dentro de una transacción sin confirmar.
- **Pendiente:**
  1. Confirmar con el director qué significa P4 en su SOC.
  2. Verificar la autenticidad del remitente con las cabeceras reales.
  3. Decidir la fecha de activación (`AUTOMATION_START_AT`).
- **Decide:** responsable de BD, que delegó en Claude («haz lo que consideres mejor»), junto con la petición de Pau recogida en WEB-004. **Estado:** implementada (migración 008), pendiente de aplicar en Azure después de la 007.

## D-006 · 03/11/2026 · Autenticidad del remitente a partir de las cabeceras del original
- **Hechos:** se revisaron en Outlook las cabeceras de un correo real del SOC (AL-20261030-0048) y de uno interno de una persona.
  - Los dos tienen `spf=pass`, `dmarc=pass` y `AuthAs: Internal`. DKIM = none, por el relay de CodeTwo.
  - Solo el del SOC lo envía un flujo de **Power Automate**.
- **Decisión:** un correo es auténtico si:
  1. El original está íntegro (SHA-256).
  2. Tiene un único From, del dominio.
  3. La **primera** cabecera Authentication-Results, la de nuestro servidor, da DMARC pass.
  4. Tiene `AuthAs Internal`.
  5. Para el SOC, además, viene de Power Automate.

  Nunca se usa el texto del correo ni `remitentes_confianza`. El bloqueo automático exige autenticidad verificada.
- **Pendiente:** confirmar que el EML exportado por Power Automate conserva esas cabeceras (BD-007). Si falta `AuthAs`, se desactiva `exigir_authas_internal` y se anota aquí.
- **Decide:** responsable de BD. **Estado:** implementada (migración 009) y probada en local con 8 casos. Pendiente de aplicar en Azure.
