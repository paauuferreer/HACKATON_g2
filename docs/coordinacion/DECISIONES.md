# Registro de decisiones — Equipo 2

Formato: ID · fecha/hora · decisión · motivo · quién decide · estado.

## D-001 · 03/11/2026 · PostgreSQL de Azure como única fuente de verdad
- **Decisión:** todos los datos (correos, alertas, clasificaciones, auditoría y bloqueos) viven en la PostgreSQL de Azure.
  La web deja de leer del almacenamiento de Sites y pasa a leer de PostgreSQL mediante rutas de API del servidor, que solo consultan las vistas `v_*`.
- **Motivo:** el enunciado fija la PostgreSQL del equipo como la base de datos del reto. Una sola fuente evita cifras distintas entre la web y la BD.
  Además, las revisiones y los bloqueos hechos desde la web hoy no llegan a PostgreSQL.
- **Transición:** la sincronización Sites → PostgreSQL (GitHub Actions) se mantiene hasta que Power Automate inserte directamente en `bandeja_entrada`.
- **Decide:** responsable de BD. **Estado:** aprobada, pendiente de implementar.

## D-002 · 03/11/2026 · Ramas y Pull Requests
- **Decisión:** nadie hace push a `main`. Ramas `bd/...` y `web/...`; merge por PR con la revisión de la otra parte.
- **Motivo:** dos IAs y varias personas sobre el mismo repo; así se evitan conflictos y queda la traza.
- **Decide:** equipo. **Estado:** propuesta, pendiente de que Pau la confirme.
