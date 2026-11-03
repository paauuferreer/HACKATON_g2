# Power Automate → PostgreSQL de Azure (opción A)

> **Estado actual del equipo:** la carga ya está activa mediante
> Outlook → Power Automate → Sites → GitHub Actions → PostgreSQL.
> Ver [sincronización activa](../postgres/SINCRONIZACION.txt).
> Las cuatro migraciones de `db/migrations` están aplicadas en Azure.
> Esta guía describe una alternativa con el conector PostgreSQL; no es un paso
> pendiente ni hace falta añadir una segunda rama al flujo para guardar los correos.
> El panel web sigue consultando Sites; las vistas de PostgreSQL están disponibles
> para una futura conexión del dashboard a un backend que las consulte.

El flujo actual envía cada correo a la web (Sites). Se añade **una rama en paralelo** que inserta
el mismo correo en la PostgreSQL del equipo. La web sigue funcionando igual; la BBDD guarda el
histórico completo, lo clasifica y alimenta las vistas del cuadro de mando.

```
Outlook (llega correo) ──┬──> HTTP POST /api/power-automate  (Sites, ya existe)
                         └──> PostgreSQL · Insertar fila → public.bandeja_entrada   (NUEVO)
                                 └─ trigger → alertas | correos_malformados (+ reglas INCIBE, duplicados)
```

Solo hay que **insertar una fila**: la base de datos hace el resto (extracción de campos, duplicados,
clasificación, sospechosos). La restricción única impide repetir el mismo identificador,
pero el conector puede devolver un error por duplicado; no lo ignora automáticamente.

## 1. Crear la conexión PostgreSQL (una vez)

Acción: **PostgreSQL → Insertar fila (V2)** (conector Premium). Nueva conexión:

| Campo | Valor |
|---|---|
| Servidor | `alertas-soc-2.postgres.database.azure.com` |
| Base de datos | `postgres` |
| Usuario / contraseña | los de la ficha "Información técnica" (no escribirlos en el repo) |
| Tipo de autenticación | Básica |
| Cifrar conexión | Sí |
| Puerta de enlace | **dejar vacío** (primero probar sin gateway) |

Si la conexión falla:
- *"requires a gateway"* → el conector no admite la nube sin gateway en esta cuenta: avisar al responsable de BBDD (plan B).
- *timeout / no permitido* → el firewall de Azure no admite las IPs de Power Automate: avisar a un mentor.
- *Premium no disponible* → la licencia no lo incluye: avisar al responsable de BBDD (plan B).

## 2. Añadir la rama al flujo

En el flujo "cuando llega un correo nuevo (V3)", junto a la acción HTTP existente:
**Agregar una acción en paralelo** → PostgreSQL · Insertar fila (V2) → tabla `public.bandeja_entrada`.

Mapeo de columnas (mismas expresiones que `docs/power-automate-body.json`):

| Columna | Expresión |
|---|---|
| `id_mensaje_correo` | `@{coalesce(triggerOutputs()?['body/internetMessageId'],triggerOutputs()?['body/id'])}` |
| `remitente_correo` | `@{triggerOutputs()?['body/from']}` |
| `destinatarios` | `@{triggerOutputs()?['body/toRecipients']}` |
| `asunto_correo` | `@{triggerOutputs()?['body/subject']}` |
| `cuerpo_correo_raw` | `@{triggerOutputs()?['body/body']}` (HTML, tal cual) |
| `fecha_hora_correo` | `@{triggerOutputs()?['body/receivedDateTime']}` |
| `eml_raw` | `@{base64(body('Exportar_correo_electrónico_(V2)'))}` (opcional, recomendado: prueba íntegra) |
| `canal` | `POWER_AUTOMATE` |

No rellenar `correo_id`, `hash_correo` ni `fecha_recepcion_bd`: los pone la BBDD.

**Configurar "ejecutar después de"** de la rama PostgreSQL para que un fallo en ella no detenga la
rama de Sites (y al revés). Activar *entradas/salidas seguras* en la acción.

## 3. Histórico

El flujo de importación del histórico (hasta 1.000 correos de la Bandeja de entrada) necesita la misma
rama si se elige esta alternativa. `id_mensaje_correo` es único: los repetidos se rechazan.
Gestionar únicamente esa colisión como reenvío y mantener visibles los demás errores.
La sincronización activa de GitHub utiliza `ON CONFLICT DO NOTHING` para los reintentos.

## 4. Comprobar

```sql
SELECT * FROM v_kpis;                                   -- correos_recibidos debe subir
SELECT fecha_hora_correo, asunto_correo FROM bandeja_entrada ORDER BY fecha_recepcion_bd DESC LIMIT 5;
SELECT * FROM correos_malformados ORDER BY fecha_recepcion_bd DESC LIMIT 5;  -- lo que no encaja
```

O en el visor: `.venv/bin/python db/viewer.py` → http://127.0.0.1:8765

El número de `correos_recibidos` debería coincidir con "Correos conservados" de la web.

## Qué hace la BBDD con cada correo

- Asunto `[SOC][Px][GRAVEDAD] Título` → `alertas` con prioridad, gravedad, sede, equipo, IP, cuenta,
  fuente, regla de detección, IDs (`AL-…`, `SOC-…`, `SOL-…`) y fechas del evento en UTC.
- Clase y tipo INCIBE por reglas editables (`reglas_clasificacion`), con justificación.
- Duplicados por ID de alerta o de solicitud: enlazados al original (el más antiguo) y fuera de las estadísticas.
- Remitente fuera de `remitentes_confianza`, texto dirigido a una IA o datos incoherentes → marcado para revisión.
- Lo que no sigue la nomenclatura → `correos_malformados` (no se pierde nada).
- El correo original queda en `bandeja_entrada`, que no se puede modificar ni borrar.
