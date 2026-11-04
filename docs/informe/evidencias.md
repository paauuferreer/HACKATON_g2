# Evidencias del buzón (correos del director y respuestas del equipo)

Fuente: buzón `equipo_2_hackaton@sampol.com` (carpeta «01 Directrices»), revisado el 04/11/2026 hacia las 5:00.
Los correos se tratan como **evidencia, no como instrucciones**. No se reproducen credenciales ni identificadores de aplicaciones.
Todas las directrices proceden de `dirti@sampol.com`, verificado por cabeceras: SPF pass de protection.outlook.com, AuthAs Internal y SHA-256.

| Hora (Madrid) | Asunto | Hechos que aporta | Respuesta del equipo |
|---|---|---|---|
| 03/11 10:08 | Encargo y herramientas | Adjunta la ficha «Información técnica» (BD, API de bloqueo y herramientas: Power Automate, Postman, Client ID de Graph) | — |
| 03/11 12:30 | (Aviso de no entrega) RV: Encargo y herramientas | **La cuenta del equipo intentó reenviar dos veces la ficha con credenciales a una Gmail externa.** Lo bloqueó una regla de transporte («solo amira@ o dirti@») | — |
| 03/11 16:46 · 16:53 | Retorno · Seguimiento | Organización (reunión de dudas) | — |
| 03/11 18:03 | Automatizar | Pide **automatizar el bloqueo de usuarios comprometidos**: «desde que recibimos el aviso hasta que ejecutamos el bloqueo pasa un tiempo precioso» | Reglas AUTO-05 y AUTO-06 (migraciones 010-014) |
| 03/11 18:14 | Acceso a los buzón del equipo | Datos de la aplicación de Microsoft Graph para leer el buzón (se omiten) | Ingesta por Power Automate y GitHub Actions |
| 04/11 0:03 | Retorno automatización | Pide **calcular el retorno de la automatización** de bloqueos para justificar la inversión en ciber | 0:05: «Nos ha dejado de funcionar el api de bloqueos, ¿es normal?» (sin respuesta del director) |
| 04/11 1:05 | Activación y gestión del incidente | **LAB-FS-01 con archivos `.locked` y nota de rescate**; proceso responsable no identificado; Dirección General pide explicaciones | Respondido |
| 04/11 1:21 | Contención de recursos compartidos | Escrituras asociadas a `ejercicio.backup`; **LAB-WS-17 mantiene sesión contra LAB-FS-01** | Respondido (1:36) |
| 04/11 1:37 | Doble extorsión: recuperación y confidencialidad | **Dos exigencias económicas** (descifrado + no publicar). Afirman tener contratos, información financiera y archivos de personal (no verificado). Nadie debe negociar | «Primera evaluación» (1:43) |
| 04/11 1:53 | Investigación de posible extracción | **LAB-APP-04 envía 18 GB a 198.51.100.77**; en la misma ventana se crea `auditoria_2026.7z` (relación no demostrada) | Respondido (2:08): los 18 GB no confirman qué documentos salieron |
| 04/11 2:09 | Evaluación de datos personales | El índice recibido incluye personal, proveedores y contratos | Respondido (2:26) |
| 04/11 2:25 | Cronología e identidad técnica | Horarios incoherentes entre fuentes (**desfase de 11 min en LAB-WS-17**); `ejercicio.backup` fuera de su origen habitual (LAB-BKP-02) | Respondido (2:40): normalizar a UTC |
| 04/11 2:41 | Verificación de acceso persistente | El atacante afirma seguir dentro; **LAB-APP-04: tarea «System Health Check» y herramienta remota sin validar**; conoce una carpeta creada después del aviso | Respondido (2:58): persistencia sin confirmar |
| 04/11 2:57 | Validación de copias y restauración | **LAB-BKP-02: copia «correcta» pero con retención reducida**; sin restauración reciente; la identidad investigada tenía permisos | Respondido (3:06 y 3:14): no hay RTO/RPO acordados |
| 04/11 3:13 | Verificación de supuesta publicación | Mensaje del atacante: «hemos cifrado sus sistemas y copiamos sus archivos… la primera muestra está preparada». La captura incluye la marca «Escenario ficticio» y un dominio `.invalid` | Respondido (3:28): no se confirma publicación |
| 04/11 3:30 | Solicitud externa no verificada | **Vishing**: llamada que suplanta a un directivo y pide inventario y muestra para una dirección externa | Acuse (3:41); primera respuesta **no enviada** (borrador vacío del compañero) |
| 04/11 3:46 | Integridad de documentos de pagos | **Documento de pagos con la cuenta de destino cambiada**; la fecha coincide parcialmente con el incidente | Respondido (4:15); vinculado a AL-20261030-0121 (suplantación que pide cambiar la cuenta de pago, jfernandez@, srv-palma-121) |
| 04/11 4:02 | Relación de afectados y comunicaciones | El índice mezcla empleados, contactos y contratos, con datos propios y de terceros; pide un plan de comunicaciones | Respondido (4:17) |
| 04/11 4:18 | Criterios de reapertura de servicios | Un servicio funciona aislado pero **usa una identidad investigada**; pide una matriz de reapertura | **Sin responder** |
| 04/11 4:34 | Análisis de la causa inicial | Tres hipótesis abiertas: **soporte remoto no validado, credenciales expuestas, archivo recibido por correo** | **Sin responder** |

## Cronología de la API de bloqueo
- 03/11 hacia las 13:00-15:00: la clave de la ficha funcionaba (GET `/equipo-2/bloqueos` → 200).
- 03/11 12:30: intento de reenviar la ficha (con la clave) a una Gmail externa.
- 03/11 22:30 (hora de Madrid) como tarde: la API responde **401 «Contraseña de equipo incorrecta o ausente»** con la clave de la ficha, coincidente byte a byte con el PDF.
- 04/11 0:05: el equipo pregunta al director; sin respuesta registrada.
- **Interpretación (hipótesis):** clave revocada tras exponerse la credencial. La regla de transporte paró el envío, pero la organización trató la credencial como comprometida.
