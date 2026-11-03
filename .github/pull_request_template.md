## Qué cambia
<!-- 1-3 líneas -->

## Área
- [ ] BD (`db/`, contrato) — revisa: equipo web
- [ ] Web (`app/`, `components/`) — revisa: responsable de BD
- [ ] Ingesta / documentación

## Checklist
- [ ] Sin credenciales, tokens ni contraseñas en el diff
- [ ] SQL parametrizado
- [ ] La web solo consulta vistas `v_*` del contrato (o este PR actualiza el contrato)
- [ ] Cambios de esquema como migración numerada e idempotente
- [ ] Ninguna llamada a `/bloquear` o `/liberar` sin aprobación humana y registro en `acciones_bloqueo`
- [ ] Decisión registrada en `docs/coordinacion/DECISIONES.md` (si aplica)

## Uso de IA
<!-- Qué IA ayudó y en qué -->
