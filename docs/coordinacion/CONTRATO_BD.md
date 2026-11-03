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

> Estado: tablas creadas en Azure. Las columnas exactas de cada vista se publicarán en `db/schema.sql` en esta misma rama.
> Hasta entonces, la web no debe depender de nombres de columna no listados aquí.
