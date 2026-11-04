# BD-014 c · Ejecutor SQL

AUTO-06 acepta la decisión SQL vinculada a acción, alerta y usuario, con fase COMPROMISO. No exige peligrosidad CRITICO: esa regla usa correlación. Revalida originales de las fases previas, remitente SOC, integridad, usuario y señales de manipulación; cuenta fases y referencias distintas. Sin evidencia suficiente queda para revisión.

MANUAL:D-007 se considera autorización ya registrada solo en modo sql: debe existir la misma fila PENDIENTE, no simulada, BLOQUEAR/USUARIO, con responsable no automático y motivo. Vuelve a leer y bloquear la fila antes de reservar; un cambio de objetivo, regla, origen o decisión impide POST. Otras acciones manuales no se seleccionan.

Permanecen protecciones de cuentas críticas/servidores, lista blanca, liberación humana, cuarentena, intención durable antes del POST, verificación GET, límites por ciclo/hora y ausencia de reintentos. Strict conserva su política. El preflight 401/403 sigue ocurriendo antes de acceder/consumir la cola. No se han ejecutado bloqueos ni cambiado el interruptor de producción.

Requiere el contrato de #5 (012/013) presente en BD. La política puede seguir rechazando objetivos protegidos o evidencia insuficiente; no se promete ejecutar toda la cola por el mero hecho de cambiar la clave. Tras revisar este PR, ejecutar preflight/dry-run antes de activar con una credencial válida.

Validación: pruebas de política, secuencia transaccional simulada, preflight sin consumo y PostgreSQL aislado en CI. No se modifica ningún fichero db/ ni reglas SQL de BD.
