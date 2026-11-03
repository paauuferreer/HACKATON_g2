# Protocolo de coordinación Claude ↔ ChatGPT ↔ Equipo 2

Las dos IAs no tienen un canal directo entre sí. **El canal es este repositorio**: ambas leen los mismos ficheros
y las personas hacen de árbitro. Así queda todo registrado, que también sirve para documentar el uso de la IA en la entrega.

## Ficheros
| Fichero | Para qué | Quién escribe |
|---|---|---|
| `AGENTS.md` (raíz) | Reglas comunes; los agentes lo leen solos | Personas |
| `CONTRATO_BD.md` | Tablas, vistas y columnas que la web puede consumir | Responsable de BD (con Claude) |
| `DECISIONES.md` | Decisiones tomadas, con su motivo | Quien decide (persona) |
| `BUZON.md` | Mensajes asíncronos entre IAs y personas | Cualquiera, añadiendo al final |

## Flujo de trabajo
1. Cada parte trabaja en su rama (`bd/...` o `web/...`) y abre un **Pull Request** a `main`.
2. La otra parte lo revisa:
   - Claude revisa los PR de web frente al contrato de BD y las reglas de seguridad.
   - ChatGPT revisa los PR de BD frente a lo que necesita el dashboard.
3. Si hay desacuerdo, cada IA deja su propuesta en el PR o en `BUZON.md` con este formato:
   **Propuesta · Motivo · Riesgo si no se hace · Alternativa aceptable**.
4. Decide una persona (BD → responsable de BD; web → Pau; dudas → todo el equipo) y lo apunta en `DECISIONES.md`.
5. Se hace merge solo con el visto bueno de las dos personas responsables.

## Cómo pedir algo a la otra IA
- **A ChatGPT:** pegarle el bloque «traspaso» que genera Claude, o decirle: «lee `AGENTS.md` y `docs/coordinacion/BUZON.md` del repo y responde a los mensajes abiertos para ChatGPT».
- **A Claude:** «mira el repo» o «revisa el PR #N».
- Si Pau tiene Codex conectado a GitHub, también se le puede invocar desde un comentario del PR.

## Reglas para evitar conflictos
- Un fichero tiene un solo dueño (ver `AGENTS.md`). Cambiar ficheros ajenos se pide, no se hace.
- El contrato de BD manda: si la web necesita una columna nueva, se pide una vista o migración, no se consulta la tabla directamente.
- Antes de cada directriz del director: merge de lo estable y tag (`v-1800`, `v-2000`, `v-0000`, `v-0800`).
