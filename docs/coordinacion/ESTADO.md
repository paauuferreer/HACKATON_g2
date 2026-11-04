# Estado compartido del Equipo 2

*Generado automáticamente el 04/11/2026 09:28 (hora de Madrid) con `docs/informe/generar_informe.py`. **Leer antes de cada tarea.** No editar a mano: se regenera con cada «actualiza».*

## Ahora mismo
- **API de bloqueo:** GET `/equipo-2/bloqueos` → **401** ({"detail":"Contraseña de equipo incorrecta o ausente."}). La API rechaza la clave (causa no confirmada) y la organización no la repondrá: no se puede ejecutar ningún bloqueo real.
- **Ingesta:** último correo guardado a las 09:13 (16 min sin correos nuevos en la BD). El cron de `postgres-sync` no se ejecuta solo: lanzar *Run workflow* si hace falta.
- **Demo:** Demostración (simulador local con el mismo contrato que la API): 13 bloqueos ejecutados y verificados y 1 liberación(es) en un clic. Es una SIMULACIÓN: sin clave válida no hay contención por API; la contención real la hizo Infra (5:30). Filas `simulacion = TRUE`, ignoradas por las vistas y los ejecutores reales.
- **BD:** migraciones 001-018 aplicadas en Azure. 257 correos, 230 alertas únicas, 20 duplicadas, 7 malformados, 11 sospechosos.
- **Cadena de ransomware:** 12 cuentas *moreno en 6 sedes, todas en fase de impacto. Siguiente estimada hacia las 05:23.

## Cola de bloqueos (`acciones_bloqueo`)
| Estado | Origen | Objetivos |
|---|---|---|
| EJECUTADA | AUTOMATICO | jmoreno@sampol.com, qgomez@sampol.com, amoreno@sampol.com, bmoreno@sampol.com, dmoreno@sampol.com, hmoreno@sampol.com, imoreno@sampol.com, vmoreno@sampol.com, lmoreno@sampol.com |
| EJECUTADA | MANUAL | cmoreno@sampol.com, emoreno@sampol.com, fmoreno@sampol.com, gmoreno@sampol.com, fmoreno@sampol.com |
| OMITIDA | AUTOMATICO | slopez@sampol.com |
| PENDIENTE | AUTOMATICO | jmoreno@sampol.com, qgomez@sampol.com, amoreno@sampol.com, bmoreno@sampol.com, dmoreno@sampol.com, hmoreno@sampol.com, imoreno@sampol.com, vmoreno@sampol.com, lmoreno@sampol.com, jfernandez@sampol.com, hmartinez@sampol.com, pgonzalez@sampol.com |
| PENDIENTE | MANUAL | cmoreno@sampol.com, emoreno@sampol.com, fmoreno@sampol.com, gmoreno@sampol.com |

Las filas `AUTOMATICO` las crean AUTO-05/AUTO-06. Las `MANUAL` (regla `MANUAL:D-007`) son decisiones humanas registradas.

## Directrices del director pendientes
| Hora | Asunto | Hechos | Estado |
|---|---|---|---|

## Tareas abiertas
| Quién | Tarea | Referencia |
|---|---|---|
| Equipo (persona) | Conseguir la clave nueva de la API por un canal seguro; ponerla en `.env` y en el secreto `BLOCK_API_KEY` | WEB-006, INFORME §6 |
| ChatGPT (web) | Ejecutor en modo sql: aceptar AUTO-06 y MANUAL:D-007 como AUTO-05 | BD-014 c |
| ChatGPT (web) | Pantallas «Cadena» (v_cadena_*) y «Costes» (docs/informe/web.json) | BD-014 b |
| ChatGPT (web) | Redactar y enviar las directrices pendientes; registrarlas en docs/directrices.md | BD-014 d |
| Claude (BD) | Con cada «actualiza»: datos, informe, ESTADO.md y revisión de los PR y mensajes WEB | BD-014 |
| Pau | Revisar y fusionar el PR de BD → main | PR bd/postgres-fuente-unica |

## Enlaces
- Informe (web): https://claude.ai/artifact/G9QhSBEQB1MfxHjh9RzMuu · Línea temporal: https://claude.ai/artifact/GmBeD6yWTeRWvt9sNW81m9 (privados; pedir acceso al responsable de BD)
- Informe completo: `docs/informe/INFORME.md` · Evidencias del director: `docs/informe/evidencias.md` · Contrato de BD: `docs/coordinacion/CONTRATO_BD.md`
