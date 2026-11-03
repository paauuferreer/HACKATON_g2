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
