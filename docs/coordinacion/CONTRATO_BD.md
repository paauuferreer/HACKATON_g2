# Contrato de base de datos (PostgreSQL de Azure)

Dueño: responsable de BD. Cualquier cambio entra como migración en `db/migrations/` y se anota aquí.
Conexión: solo desde el servidor, con TLS y variables de entorno (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`). Nunca desde el navegador.

## Flujo de datos
`Outlook → Power Automate → public.bandeja_entrada (inmutable) → trigger procesar_correo() → public.alertas | public.correos_malformados`

## Tablas (esquema `public`)
| Tabla | Rol | Quién escribe |
|---|---|---|
| `bandeja_entrada` | Correo original íntegro e inmutable (EML, cabeceras, hash) | Ingesta (solo INSERT) |
| `alertas` | Una fila por alerta SOC; estado, prioridad, peligrosidad, INCIBE, duplicados | Trigger + revisión humana |
| `correos_malformados` | Correos que no son alerta SOC válida, con el motivo | Trigger + revisión humana |
| `historial_cambios_alertas` | Auditoría de estado y categoría (anterior → nuevo, quién, cuándo) | Trigger |
| `acciones_bloqueo` | Llamadas a la API de bloqueo con su respuesta | Backend web, tras aprobación |
| `incibe_clases`, `incibe_tipos` | Taxonomía INCIBE | BD (catálogo) |
| `reglas_clasificacion`, `remitentes_confianza` | Reglas deterministas y remitentes válidos | BD |

El esquema `pruebas` contiene datos ficticios: la web no lo consulta nunca.

## Lo que la web puede consumir (solo lectura)
| Vista | Uso en el dashboard |
|---|---|
| `v_kpis` | Tarjetas de resumen |
| `v_alertas` | Listado y detalle (sin duplicados) |
| `v_stats_*` | Gráficos por clase INCIBE, fuente y gravedad |
| `v_top_equipos`, `v_top_usuarios`, `v_top_ips` | Rankings |
| `v_timeline` | Línea temporal |
| `v_inconsistencias` | Correos manipulados o incoherentes |
| `v_solicitudes` | Solicitudes de bloqueo y liberación |

**Escrituras permitidas a la web** (siempre parametrizadas y desde el servidor):
- Cambiar el estado o la categoría de una alerta: `UPDATE alertas` (el trigger audita; hay que rellenar `usuario_analista`).
- Registrar una acción de bloqueo: `INSERT INTO acciones_bloqueo`.

## Bloqueo automático de nivel 2 (migración 005, decisión D-003)
Flujo: alerta crítica → `trigger_bloqueo_auto` → `evaluar_bloqueo_auto()` → fila `PENDIENTE` en `acciones_bloqueo`
→ `soc/ejecutor_bloqueos.py` llama a la API → `EJECUTADA` o `ERROR` con la respuesta guardada.

| Objeto | Para la web |
|---|---|
| `v_bloqueos_activos` | Qué IPs y usuarios están bloqueados ahora (incluye los encolados) |
| `v_decisiones_bloqueo` | Por qué se bloqueó o se descartó cada objetivo de cada alerta crítica |
| `lista_blanca` | CRUD desde la web: usuarios, IPs o rangos que nunca se bloquean solos |
| `reglas_bloqueo_auto` | Ver y activar/desactivar reglas (filtros: prioridad, peligrosidad, clase INCIBE, nº de alertas en ventana, solo IP pública, remitente de confianza) |
| `SELECT solicitar_liberacion($1 tipo, $2 valor, $3 responsable, $4 motivo)` | Botón «Liberar» (un clic). `tipo` = `'IP'` o `'USUARIO'` |

Bloqueo manual desde la web: `INSERT INTO acciones_bloqueo (accion, ip_objetivo | usuario_objetivo, motivo, solicitado_por, estado, origen) VALUES ('BLOQUEAR', …, 'PENDIENTE', 'MANUAL')`. Una fila = un solo objetivo. La web **nunca** llama a la API directamente: lo hace el ejecutor.

## Ajustes del bloqueo y contrato del ejecutor (migración 008, decisión D-005)
- **Decisiones posibles:** `BLOQUEAR`, `YA_BLOQUEADO`, `RECOMENDAR` (cumple todo, pero es una IP o la alerta tiene más de 15 min: decide una persona) y `DESCARTAR`.
- **Estados de `acciones_bloqueo`:** `PENDIENTE` → `EN_CURSO` (intención guardada antes del POST) → `EJECUTADA` | `ERROR` (fallo conocido) | `DESCONOCIDO` (cuarentena). También `OMITIDA` (no se envió).
- **Ejecutor:** `reservar_accion_bloqueo(accion_id) → token` y COMMIT; luego el POST; luego `cerrar_accion_bloqueo(accion_id, token, resultado, http, respuesta)` y COMMIT. Si cae entre medias, queda `EN_CURSO` y nunca se repite el POST. Las dudas las resuelve una persona con `reconciliar_accion_bloqueo(accion_id, 'EJECUTADA'|'ERROR', responsable, motivo)`.
- **Compatibilidad:** `ERROR` + `respuesta_api.automation.phase` = `outcome_unknown`/`acknowledged` cuenta como cuarentena (`es_cuarentena()`).

| Vista | Uso |
|---|---|
| `v_bloqueos_activos` | Añade `confirmado` (la API lo aceptó y no hay liberación posterior), `en_cuarentena` y `fase_automatizacion`. **Solo `confirmado` significa bloqueado.** |
| `v_recomendaciones_bloqueo` | Objetivos recomendados aún no bloqueados: botón «Bloquear» manual |
| `v_bloqueos_revision` | Operaciones `ERROR`, `DESCONOCIDO`, `EN_CURSO` y `OMITIDA` que necesitan a una persona |
| `v_evidencias_automatizacion` | Una fila por `correo_id` con el EML y las cabeceras. `autenticacion_verificada` vale **FALSE** hasta implementar la verificación con cabeceras del servidor de correo |

Columnas nuevas de `reglas_bloqueo_auto`: `antiguedad_max_minutos` (15), `exigir_criticidad_cuerpo`, `inconsistencias_ignoradas` (patrones LIKE) e `ip_automatica` (FALSE).

## Autenticidad del remitente (migración 009, decisión D-006)
`autenticidad_correo(correo_id)` → `verificada, metodo, emisor, motivo, integridad_ok`. Solo usa el original EML y su SHA-256. Las comprobaciones, en orden:
1. Un único `From`, igual a `remitente_correo` y del dominio `sampol.com`.
2. La **primera** cabecera `Authentication-Results` la firma `mx.microsoft.com` e indica `dmarc=pass` con `header.from=sampol.com`.
3. `X-MS-Exchange-Organization-AuthAs: Internal`.
4. Para `soc-hackaton@`, además: `x-ms-mail-application: Microsoft Power Automate`.

La configuración está en `config_autenticacion`. Las reglas de bloqueo tienen `requiere_autenticacion` (TRUE por defecto).

| Vista | Uso |
|---|---|
| `v_evidencias_automatizacion` | Contrato del ejecutor web: ahora con valores reales, más `autenticacion_motivo` e `integridad_ok` al final |
| `v_autenticidad_correos` | Por correo: verificado o no y por qué. También sirve para validar las directrices del director |
| `v_autenticidad_resumen` | Recuento por remitente y motivo, sin contenidos |

## Extracción y casos claros (migraciones 007 y 010, decisión D-007)
- **007:** `texto_plano()` colapsa los espacios del HTML antes de convertir las etiquetas. Con eso se extraen bien usuario, equipo, sede, fuente, regla y criticidad del cuerpo. `reprocesar_alertas()` regenera las alertas desde la bandeja, solo si ninguna tiene revisión humana ni acciones de bloqueo.
- **010, `autenticidad_correo()`:** en correo interno sin `Authentication-Results` se verifica con:
  - la primera `Received-SPF` pass de `protection.outlook.com` para el dominio;
  - `AuthAs Internal`, `AuthMechanism` y `AuthSource`;
  - un único From;
  - SHA-256.

  Método: «Exchange interno: SPF pass + AuthAs Internal + SHA-256». Configuración en `config_autenticacion`: `aceptar_interno_sin_ar`, `verificador_spf` y `exigir_power_automate` (FALSE).
- **010, regla AUTO-05** (AUTO-04 desactivada):
  - asunto CRÍTICO con cualquier Px;
  - cuerpo en `criticidades_cuerpo` ({critic, alt}), o en `criticidades_corroboradas` ({medi, baj}) con al menos `min_alertas_corroboracion` (2) alertas críticas del usuario en `ventana_corroboracion_min` (120). Sin esa corroboración, RECOMENDAR;
  - sin antigüedad máxima;
  - `inconsistencias_solo_ip`: una IP mal escrita no impide bloquear al usuario.
- **010, `es_cuenta_protegida(usuario)`:** las cuentas de servicio o administración nunca se bloquean solas (RECOMENDAR). Las cuentas de otro dominio se descartan.

## Cadena de ransomware y detección temprana (migraciones 012-014, decisión D-009)
- `fases_ataque`: fase, orden y patrón sobre el título plegado (editable). `fase_de_titulo(titulo)` devuelve la fase.
- Vistas (solo lectura; horas en Europe/Madrid; «aviso» = llegada del correo):

| Vista | Uso |
|---|---|
| `v_fases_alertas` | Alerta → víctima (inferida por equipo si falta el usuario), fase y fechas |
| `v_cadena_victimas` | Cuentas con al menos 3 fases: orden, equipos, sedes, fase máxima, `min_ganados_detectando_compromiso` y estado del bloqueo |
| `v_cadena_ransomware` | Detalle por fase con `min_desde_fase_anterior` y `min_desde_inicio_victima` |
| `v_cadena_prediccion` | Ritmo medio entre víctimas y hora estimada de la siguiente (evento y aviso) |

- **Regla AUTO-06:**
  - se evalúa con `evaluar_cadena_compromiso(alerta)`, mediante el trigger `trigger_cadena_compromiso`, o con `evaluar_cadena_pendientes(horas)`;
  - columnas `fase_disparadora`, `fases_previas` y `min_fases_previas`;
  - tiene las peligrosidades vacías, así que `evaluar_bloqueo_auto()` nunca la elige.
- **014:** la corroboración y `min_alertas` cuentan IDs del SOC distintos, no filas.

## Analítica temporal (migración 006, decisión D-004)
Horas en Europe/Madrid. Columnas: `total` (carga, sin duplicados), `reales` (sin falsas alarmas ni no-SOC), `criticas`, `p1`.

| Vista | Uso |
|---|---|
| `v_heatmap_dia_hora` | Mapa de calor día de la semana × hora (168 celdas, incluidas las vacías) |
| `v_stats_franja` | Carga por franja (laboral, guardia tarde, fin de semana/festivo, guardia noche) y `coste_manual_eur` cuando Administración rellene `franjas_horarias.coste_hora_eur` y `parametros_negocio` |
| `v_stats_periodo` | `WHERE granularidad IN ('hora','dia','semana','mes','anio')`: evolución y estadísticas mensuales y anuales |
| `v_picos_hora` | Horas con más del doble de la media de las 24 h previas |
| `v_timeline_geopolitica` | Alertas por día, picos y eventos de `eventos_geopoliticos` activos ese día |

**Exportación:** todas las vistas `v_*` son tablas planas; la web ofrece «Descargar CSV» de la vista que se esté viendo.

> Estado: tablas creadas en Azure. Las columnas exactas de cada vista se publicarán en `db/schema.sql` en esta misma rama.
> Hasta entonces, la web no debe depender de nombres de columna no listados aquí.

## Organización del buzón de Outlook (migración 011, decisión D-008)
**Carpeta = qué hacer con el correo** (una por correo). **Etiqueta = qué es** (varias): gravedad, clase INCIBE y señales. Lo decide la BD; `soc/outlook_organizar.py` lo aplica con Graph.

| Objeto | Uso |
|---|---|
| `config_outlook` | Interruptor `organizacion_activa`, remitentes de directrices y del SOC |
| `outlook_carpetas`, `outlook_categorias` | Rutas, nombres y colores editables (sin tocar código) |
| `v_outlook_destino` | Por correo: `carpeta_ruta`, `categorias[]`, `motivo` y `huella`. La web puede mostrar «dónde está en Outlook» |
| `v_outlook_pendientes` | Lo que falta aplicar (nuevos, con cambios, o errores a reintentar tras 10 min, máximo 6 intentos) |
| `v_outlook_resumen` | Correos, aplicados y pendientes por carpeta |
| `outlook_sincronizacion` + `registrar_sincronizacion_outlook()` | Auditoría de lo aplicado (id de Graph, estado, detalle) |

Reglas de carpeta, por orden:
1. Cuarentena: motivo real de sospecha, autenticidad fallida o sin cabeceras de transporte.
2. Directrices.
3. Cuarentena: formato de alerta SOC desde un remitente que no es el SOC.
4. No SOC: remitente externo.
5. SOC · Revisión manual: correo del SOC sin formato.
6. No SOC: resto de correos malformados.
7. Solicitudes.
8. Ruido: duplicados, falsas alarmas e informativos.
9. No SOC: alertas en estado NO_SOC.
10. SOC · Cerradas.
11. SOC · Críticas y altas: el asunto o el cuerpo dicen crítico o alto.
12. SOC · Medias y bajas.

Los correos aún sin procesar se quedan en la Bandeja de entrada.

## Organización de Outlook: ajustes del despliegue (migraciones 015 y 016, BD-011)
- **015:** en `v_outlook_destino`, el motivo «Menciona herramientas de IA o prompts» deja de mandar a cuarentena **solo** si el remitente es externo, el correo tiene cabeceras de transporte, no es una alerta del SOC y no intenta imponer una clasificación. Ese correo pasa a «06 No SOC». Las mismas columnas que en la 011.
- **016, plan B sin Client ID:** Power Automate ordena el buzón con su conexión de Outlook (guía en `docs/POWER-AUTOMATE-OUTLOOK.md`).

| Objeto | Uso |
|---|---|
| `v_outlook_pendientes_pa` | Cola para Power Automate: `correo_id` (texto), `id_outlook`, `carpeta_codigo`, `carpeta_ruta`, `categorias_json`, `huella`, `fecha_hora_correo`. Vacía si `config_outlook.organizacion_activa` es FALSE |
| `outlook_resultados_pa` | Power Automate **solo inserta** (`correo_id`, `huella`, `carpeta_codigo`, `graph_message_id`, `estado` APLICADO/NO_ENCONTRADO/ERROR, `detalle`). El trigger lo registra con `registrar_sincronizacion_outlook()` |
