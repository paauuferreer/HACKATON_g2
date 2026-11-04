# Power Automate ordena el buzón de Outlook (plan B de BD-011)

El script `soc/outlook_organizar.py` necesita iniciar sesión en Microsoft Graph con un Client ID, y ese inicio
de sesión no se pudo completar. Este flujo hace el mismo trabajo con la conexión de Outlook que Power Automate
ya tiene con el buzón del equipo. **La base de datos sigue decidiendo** la carpeta y las etiquetas de cada correo
(`v_outlook_destino`, migraciones 011 y 015). El flujo solo lee la cola, mueve y devuelve el resultado.

```
cada 5 min ─> PostgreSQL: Obtener filas  public.v_outlook_pendientes_pa   (hasta 50)
               └─ para cada correo:
                    Outlook: Enviar una solicitud HTTP  GET  (buscar el correo por internetMessageId)
                    ¿encontrado?
                      sí ─> Outlook: Enviar una solicitud HTTP  PATCH  (etiquetas)
                            Switch carpeta_codigo ─> Outlook: Mover correo electrónico (V2)
                            PostgreSQL: Insertar fila  outlook_resultados_pa   (APLICADO)
                      no ─> PostgreSQL: Insertar fila  outlook_resultados_pa   (NO_ENCONTRADO)
```

Volver a ejecutarlo no repite trabajo: un correo sale de la cola en cuanto se registra como aplicado, y vuelve a
entrar solo si la base de datos cambia su destino (por ejemplo, al revisarlo una persona). El histórico (166
correos) se ordena solo, a razón de 50 cada 5 minutos.

## 0. Antes de empezar (una vez)

1. En Outlook, dentro de **Bandeja de entrada**, crea estas carpetas (mismo nombre exacto):

   | Código (BD) | Carpeta |
   |---|---|
   | `DIRECTRICES` | 01 Directrices |
   | `SOC_CRITICAS` | 02 SOC → Críticas y altas |
   | `SOC_MEDIAS` | 02 SOC → Medias y bajas |
   | `SOC_REVISION` | 02 SOC → Revisión manual |
   | `SOC_CERRADAS` | 02 SOC → Cerradas |
   | `SOLICITUDES` | 03 Solicitudes (SOL) |
   | `RUIDO` | 04 Ruido |
   | `CUARENTENA` | 05 Cuarentena |
   | `NO_SOC` | 06 No SOC |

   «Críticas y altas», «Medias y bajas», «Revisión manual» y «Cerradas» son subcarpetas de «02 SOC».
2. Conexión **PostgreSQL**: la misma que usa la rama «Insertar fila» (`docs/POWER-AUTOMATE-POSTGRESQL.md`).
3. Conexión **Office 365 Outlook** con la cuenta del buzón del equipo (la del flujo de ingesta).

## 1. Crear el flujo

**Crear → Flujo de nube programado**. Nombre: `Organizar buzón (BD)`. Repetir cada **5 minutos**.

### 1.1 PostgreSQL · Obtener filas (V2)
| Campo | Valor |
|---|---|
| Nombre de tabla | `public.v_outlook_pendientes_pa` (si no sale en la lista: *Escribir un valor personalizado*) |
| Ordenar por | `fecha_hora_correo` |
| Recuento superior | `50` |

### 1.2 Aplicar a cada uno
- Entrada: `value` de *Obtener filas*.
- En *Configuración*, activa **Control de simultaneidad** con grado **1** (un correo cada vez).

Dentro de *Aplicar a cada uno*, en este orden:

#### a) Office 365 Outlook · Enviar una solicitud HTTP — renómbrala `Buscar correo`
| Campo | Valor |
|---|---|
| URI | `https://graph.microsoft.com/v1.0/me/messages?$select=id&$filter=internetMessageId eq '@{encodeUriComponent(items('Aplicar_a_cada_uno')?['id_outlook'])}'` |
| Método | `GET` |

#### b) Componer — renómbrala `IdOutlook`
Entradas (expresión): `first(body('Buscar_correo')?['value'])?['id']`

#### c) Condición: `IdOutlook` **no está vacío** → expresión `empty(outputs('IdOutlook'))` es igual a `false`

**Rama «Sí»:**

1. **Office 365 Outlook · Enviar una solicitud HTTP** — renómbrala `Etiquetar`
   | Campo | Valor |
   |---|---|
   | URI | `https://graph.microsoft.com/v1.0/me/messages/@{outputs('IdOutlook')}` |
   | Método | `PATCH` |
   | Cuerpo | `{"categories": @{items('Aplicar_a_cada_uno')?['categorias_json']}}` |
   | Content-Type | `application/json` |

   Va **antes** de mover, porque al mover cambia el id del correo. Las etiquetas aparecen sin color: el color
   necesita un permiso de configuración del buzón que no hace falta para ordenar.
2. **Switch** sobre `items('Aplicar_a_cada_uno')?['carpeta_codigo']`, con un caso por código de la tabla del
   punto 0. En cada caso, **Office 365 Outlook · Mover correo electrónico (V2)**:
   - Id. del mensaje: `outputs('IdOutlook')`
   - Carpeta: elige en el selector la carpeta de ese código.
3. **PostgreSQL · Insertar fila (V2)** en `public.outlook_resultados_pa`:
   | Columna | Valor |
   |---|---|
   | `correo_id` | `items('Aplicar_a_cada_uno')?['correo_id']` |
   | `huella` | `items('Aplicar_a_cada_uno')?['huella']` |
   | `carpeta_codigo` | `items('Aplicar_a_cada_uno')?['carpeta_codigo']` |
   | `graph_message_id` | `outputs('IdOutlook')` |
   | `estado` | `APLICADO` |
   | `detalle` | `Power Automate` |

**Rama «No»** (el correo no está en el buzón: borrado, movido a mano o de otro buzón):

- **PostgreSQL · Insertar fila (V2)** en `public.outlook_resultados_pa`, igual que arriba pero con
  `estado` = `NO_ENCONTRADO` y sin `graph_message_id`.

#### d) Errores (recomendado)
Mete a), b), c) en un **Ámbito** (*Scope*). Después del ámbito, añade **PostgreSQL · Insertar fila (V2)** con
`estado` = `ERROR` y `detalle` = `@{result('Ámbito')?[0]?['error']?['message']}`, configurado en
*Configurar ejecución posterior* para ejecutarse **solo si el ámbito falla**. Los errores se reintentan solos
(hasta 5 veces, con 10 min de espera), igual que con el script.

## 2. Probar

1. **Prueba** del flujo → *Manualmente* → *Guardar y probar*. La primera ejecución mueve los 50 correos más
   antiguos.
2. Comprobar en la BD (solo recuentos):
   ```sql
   SELECT estado, count(*) FROM outlook_sincronizacion GROUP BY 1;
   SELECT count(*) AS pendientes FROM v_outlook_pendientes;      -- baja de 50 en 50 hasta 0
   SELECT ruta, correos FROM v_outlook_resumen ORDER BY orden;   -- lo que debería haber en cada carpeta
   ```
3. En Outlook, cada carpeta debe tener tantos correos como dice `v_outlook_resumen`.

## Qué hace y qué no hace
- **No** decide nada: si una carpeta o etiqueta no gusta, se cambia la regla en la BD (`v_outlook_destino`),
  nunca el flujo.
- **No** borra correos ni los marca como leídos. Mover un correo no afecta al flujo de ingesta, que se dispara al
  llegar a la Bandeja de entrada.
- El interruptor general es `config_outlook.organizacion_activa`. Para pararlo del todo, desactiva el flujo.
