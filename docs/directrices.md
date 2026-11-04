# Registro de directrices · BD-014 d

Fecha: 04/11/2026. Horas Europe/Madrid (UTC+1). Envíos verificados en Elementos enviados de equipo_2_hackaton@sampol.com; esta evidencia confirma envío, no lectura o entrega al destinatario. Destinatario único: dirti@sampol.com; sin CC/CCO externos.

## Verificación y límites

Se han abierto los tres originales y comprobado From y Reply-To dirti@sampol.com, SPF pass de protection.outlook.com y X-MS-Exchange-Organization-AuthAs Internal en Ver detalles del mensaje. No se ha calculado un SHA-256 nuevo del EML durante esta revisión UI; el informe de BD declara su verificación previa. No se publican cabeceras completas ni originales. Hechos basados en INFORME.md y evidencias.md de ff69b9e y contrastados con los originales.

Antes de enviar se revisaron los enviados: Análisis de la causa inicial ya tenía acuse y respuesta automática a las 04:34. Por ello se envió una ampliación correctiva, no un nuevo acuse. El borrador del compañero de Solicitud externa (guardado 04:36) se ha conservado sin editar ni borrar; se creó otra respuesta al original.

| Directriz | Recepción visible | Primera respuesta observada | Envío de esta tarea | Resultado |
|---|---|---|---|---|
| Reapertura | 04:18 | No localizada anteriormente | 05:58 | Matriz y condiciones; fuera de plazo (límite 04:38) |
| Causa inicial | 04:34 | Acuse y respuesta automáticos 04:34 | 05:59 | Ampliación y corrección de afirmaciones no acreditadas |
| Solicitud externa | 03:30 (Date 03:29:58) | Acuse 03:41, sin evaluación sustantiva | 06:01 | Primera evaluación; fuera de plazo (límite aproximado 03:50) |

No se ha realizado contención, reapertura, contacto con terceros ni ninguna de las comprobaciones forenses propuestas. Responsables propuestos, no asignaciones aceptadas.

## Reapertura · enviado 05:58

Primera evaluación — reapertura

El servicio funciona aislado, pero utiliza una identidad investigada y faltan pruebas funcionales y de integridad. Recomendamos mantenerlo aislado; funcionamiento no equivale a autorización de reapertura.

Matriz propuesta (responsables por confirmar):
• Identidad: pendiente sustituir o sanear credenciales y sesiones, y validar privilegios. Responsable propuesto: Identidades/Seguridad.
• Configuración y datos: pendiente contrastar configuración, persistencia e integridad con una referencia fiable. Responsable: Infraestructura/Forense.
• Servicio y dependencias: pendiente prueba funcional y restauración aislada; priorizar con negocio por criticidad. Responsable: Operaciones y dueño del servicio.
• Aceptación: pendiente aprobación expresa de Dirección TI y negocio, con riesgo residual y RTO/RPO acordados.

Solo proponemos reapertura gradual tras documentar esas pruebas, con vigilancia reforzada y retirada inmediata ante nuevas escrituras anómalas, accesos de la identidad investigada o fallos de integridad. La investigación de exposición continúa por separado.

Siguiente acción: designar responsables y completar la matriz con evidencias y horas de prueba. No damos ninguna validación ni reapertura por ejecutada. Esta respuesta llega fuera del plazo original; se registrará la hora real.

Equipo 2

## Causa inicial · enviado 05:59

Ampliación y precisión de la respuesta automática de las 4:34

La causa inicial sigue sin determinarse. No existe una cadena demostrada hasta extracción y cifrado. Rectificamos: no hay evidencia suficiente para afirmar qué controles fallaron o carecían de cobertura; tampoco corresponde iniciar negociación por iniciativa propia.

Hipótesis y prueba pendiente:
• Soporte remoto: a favor, herramienta sin validar y tarea «System Health Check» en LAB-APP-04. Faltan fecha de instalación, aprobación y registros de acceso/ejecución. Su presencia no demuestra que fuera la entrada.
• Credenciales: a favor, uso de ejercicio.backup fuera de su origen habitual. Faltan autenticaciones, sesiones, elevaciones y origen de la exposición. Un acceso válido no identifica por sí solo al atacante.
• Archivo por correo: hipótesis abierta; falta vincular un mensaje/adjunto con descarga, proceso hijo y primer acceso.

No consta evidencia concluyente contraria a ninguna. Separaremos acceso inicial, privilegios, persistencia, movimiento lateral, extracción y cifrado, normalizando horarios (LAB-WS-17 tiene 11 minutos de desfase). Los 18 GB y auditoria_2026.7z coinciden temporalmente, sin vínculo demostrado.

Proponemos priorizar la hipótesis remota como línea de trabajo, no como conclusión. Quedaría descartada como entrada si una cronología íntegra acredita el compromiso previo a su instalación y excluye otro acceso remoto anterior. Necesitamos EDR, autenticaciones, registros de la herramienta, correo original y analista forense. Dirección debe asignar responsables y recursos; la alternativa de restaurar sin preservar evidencia puede impedir determinar la causa. Ninguna comprobación se da por realizada.

Equipo 2

## Solicitud externa · enviado 06:01

Primera evaluación — solicitud externa no verificada

Hecho comunicado: un interlocutor atribuye su petición a un directivo y solicita inventario y una muestra para una dirección externa, sin confirmación independiente. Es compatible con vishing; no acredita identidad, autorización de asesoría ni compromiso del canal. No consta si el técnico llegó a transmitir datos.

Recomendamos suspender esa entrega y verificar con el directivo y Jurídico mediante números y canales del directorio interno, nunca los facilitados por la llamada. Solicitar al técnico destinatario, contenido, medio y hora de cualquier envío; preservar llamadas, mensajes y registros de correo/transferencia. Revisar sesiones y miembros del canal de crisis antes de atribuir un compromiso.

Para cualquier entrega proponemos autorización documentada del responsable del incidente y del propietario de la información, con Jurídico/Privacidad cuando corresponda; destinatario verificado, contenido mínimo, canal corporativo cifrado y registro de lo compartido. Hasta entonces, ninguna entrega externa.

La exposición adicional sigue sin determinarse. Siguiente acción propuesta: asignar un responsable de verificación y contrastar el testimonio con registros de salida. No damos esas comprobaciones por realizadas. Esta evaluación llega fuera del plazo original; se registra la hora real.

Equipo 2
