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

## D-007 · 03/11/2026 · Bloqueo automático de usuarios en casos claros, también con las alertas ya recibidas
- **Hechos:**
  - Las 14 alertas críticas llegan como `[P4][CRÍTICO]`.
  - Las plantillas del SOC dicen siempre «Pendiente de validación».
  - El EML guardado de los correos internos no trae `Authentication-Results` (0 de 111) ni `x-ms-mail-application` (0 de 111). Sí trae `Received-SPF: Pass` de `protection.outlook.com`, `AuthAs Internal`, `AuthMechanism` y `AuthSource`.
  - Con la 009 tal cual no se verificaba ningún correo del SOC, y con D-005 no se bloqueaba nada.
- **Feedback del director (vía el responsable de BD):** la prioridad no es fiable, porque puede ser P4 según INCIBE, pero una alerta CRÍTICA no puede quedar como «Otros». Bloqueo automático en casos claros, empezando ya.
- **Decisión (regla AUTO-05, migración 010; AUTO-04 desactivada):**
  - **Se bloquea un usuario automáticamente si se cumple todo esto:**
    - asunto CRÍTICO con cualquier Px;
    - cuerpo Crítica o Alta. Media o Baja solo valen si hay al menos 2 alertas críticas del mismo usuario en 2 h; si no, RECOMENDAR;
    - clase INTRUSION, CONTENIDO_DANINO o COMPROMISO_INFORMACION;
    - remitente de confianza autenticado. En correo interno: primera `Received-SPF` pass + `AuthAs Internal` + `AuthMechanism` + `AuthSource` + un único From + SHA-256;
    - cuenta personal `@sampol.com`.
  - **Se mantienen los filtros de siempre:** sin petición SOL, sin sospecha, sin duplicado, fuera de la lista blanca y sin liberación humana posterior.
  - **Ajustes:**
    - una IP mal escrita invalida la IP, no al usuario;
    - las cuentas de servicio o administración, las IPs y los casos sin corroborar pasan a RECOMENDAR;
    - no hay antigüedad máxima: entran las alertas ya recibidas.
  - Power Automate deja de exigirse (`config_autenticacion.exigir_power_automate = FALSE`) mientras el EML no conserve esa cabecera.
- **Resultado en Azure (03/11 22:50):**
  - 5 usuarios encolados para bloquear (`PENDIENTE`): qgomez, jmoreno, amoreno, bmoreno y dmoreno.
  - 6 decisiones RECOMENDAR de usuario y 7 de IP.
  - No se ha enviado ningún POST.
- **Pendiente:**
  1. La clave de la API da 401: hay que conseguir la nueva de la organización.
  2. Adaptar el ejecutor web a la decisión SQL (BD-010).
  3. El OK final del equipo para activar `BLOQUEO_AUTO_ACTIVO=1`.
- **Decide:** responsable de BD, con la petición del director. Lista revisada en simulación antes de encolar. **Estado:** implementada (010), aplicada en Azure.

## D-008 · 04/11/2026 · El buzón de Outlook se ordena solo, según la base de datos
- **Petición:** que la bandeja de entrada esté organizada con carpetas y etiquetas según el correo que llegue. No aparece en los documentos del reto: llegó por otra vía y falta documentar su origen; si es una directriz, va también a `docs/directrices.md`.
- **Decisión:**
  - **Carpeta = qué hay que hacer** (Directrices, SOC por urgencia, Revisión manual, Cerradas, Solicitudes, Ruido, Cuarentena, No SOC).
  - **Etiquetas de color = qué es** (gravedad, clase INCIBE, verificado/sospechoso, duplicado, inconsistente, solicitud, bloqueo).
  - Lo decide la BD (vista `v_outlook_destino`), con la misma clasificación que el cuadro de mando. Lo aplica `soc/outlook_organizar.py` con Graph.
- **Alternativa descartada:** reglas de Outlook que mueven correos al llegar. El flujo de Power Automate se dispara en la Bandeja de entrada y podría no ver el correo; además, esas reglas solo ven el asunto y el remitente, que se pueden falsificar.
- **Detalle de seguridad:** `procesar_correo()` marca como sospechoso a cualquier remitente fuera de la lista de confianza. Para el buzón solo cuentan los motivos reales. Así, los avisos de la organización y de servicios van a «No SOC», no a Cuarentena.
- **Seguridad del script:**
  - Solo mueve correos ya guardados en la BD.
  - Nunca interpreta su contenido.
  - Conserva las etiquetas puestas a mano.
  - Arranca en simulación.
  - Necesita `Mail.ReadWrite` delegado; `MailboxSettings.ReadWrite` es opcional y solo sirve para los colores.
- **Decide:** responsable de BD. **Estado:** implementada (migración 011) y probada en local con 14 correos. Pendiente de aplicar en Azure y de ejecutar el script.

## D-009 · 03/11/2026 · Detección temprana de la cadena de ransomware (AUTO-06) y contención preventiva
- **Hechos:** el buzón muestra una intrusión que salta de cuenta en cuenta cada ~72 min (jmoreno → amoreno → cmoreno → bmoreno → dmoreno → emoreno → fmoreno → gmoreno; equipos 201-208 en seis sedes).
  - **Vía de credenciales:** phishing → fuerza bruta → acceso no reconocido → lectura indebida → mando y control → alteración de ficheros.
  - **Vía de explotación:** sondeo de puertos → petición con explotación → proceso anómalo → mando y control → alteración.
  - El acceso no reconocido llega **39-46 min antes** que la primera alerta crítica.
- **Decisión:**
  - **Fases del ataque** (migración 012): se asignan por el título, con una tabla editable. Vistas `v_fases_alertas`, `v_cadena_victimas`, `v_cadena_ransomware` y `v_cadena_prediccion`.
  - **Regla AUTO-06** (migración 013): bloquea al usuario cuando hay cuenta comprometida precedida de phishing o fuerza bruta en 2 h. Mismos filtros de seguridad que AUTO-05; ignora la discrepancia de gravedad entre asunto y cuerpo, porque aquí la prueba es la secuencia.
  - **Simulación:** reconoce las 5 víctimas de la vía de credenciales, descarta los 6 accesos sueltos y da 0 falsos positivos.
  - **Contención preventiva manual** (equipo, D-007): fmoreno (acceso no reconocido, 22:41) y gmoreno (explotación, 23:33).
- **Corrección (migración 014):** la corroboración contaba el reenvío de la misma alerta como una segunda alerta. slopez@ pasó a BLOQUEAR por error. Ahora se cuentan IDs del SOC distintos; slopez pasa a RECOMENDAR y su acción queda OMITIDA (nunca se envió).
- **Decide:** responsable de BD. **Estado:** aplicada en Azure (el 03/11 con los nombres 011-013; renumeradas a 012-014 el 04/11 porque la 011 pasó a ser la organización de Outlook). Línea temporal para la presentación publicada como página (privada; compartir desde su menú).
