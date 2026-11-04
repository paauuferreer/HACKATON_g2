# BD-014 b · Cadena y Costes

Rama independiente sobre main. Requiere integrar PR #5 (contrato 012 y docs/informe/web.json).

1. En un checkout que incluya #5, ejecutar `node services/postgres-api/scripts/prepare-report.mjs` antes de empaquetar el servicio. Falla si falta el informe. Copia solo fecha e importes al directorio privado report/ (ignorado por Git).
2. Desplegar services/postgres-api en Vercel incluyendo report/web.json. vercel.json incorpora el archivo a las funciones. Repetir preparación/despliegue cuando BD regenere el informe.
3. Desplegar la ruta de Sites actualizada y configurar SOC_ANALYTICS_BACKEND_URL con la URL HTTPS de Vercel; reutiliza SOC_BACKEND_TOKEN y la lista de lectores. Esta variable separa la investigación del traspaso completo del backend.
4. Publicar Pages después de la revisión. Conectar sesión privada y abrir Cadena/Costes. Sin backend o contrato devuelve indisponibilidad explícita, nunca datos ficticios.

Cadena consulta exclusivamente v_cadena_victimas, v_cadena_ransomware y v_cadena_prediccion, en transacción de lectura consistente. Paginación de 50 víctimas con parámetros. Conserva horas locales de Madrid sin reinterpretarlas como UTC; muestra eventos y avisos, usuario inferido, predicción histórica y bloqueo confirmado separado de pendiente.
Costes muestra importes generados (sin recalcular escenarios), fecha y fuente; ahorro potencial no equivale a ahorro realizado. No incluye víctimas ni originales en la respuesta económica ni en el bundle público.

Validación: build Pages; pruebas backend de autenticación y contrato; nuevas pruebas de privacidad del informe, paginación parametrizada y rollback. No desplegado ni conectado a datos reales por este PR.
