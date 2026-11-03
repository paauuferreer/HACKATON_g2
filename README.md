# HACKATON_g2 — Hackapol SOC

Web privada para el equipo 2: recepción de Outlook mediante Power Automate,
clasificación explicable por prioridad y clases INCIBE, revisión, evidencias,
auditoría y contención autorizada mediante la API del hackatón.

- Solo datos reales en la interfaz; actualización cada 10 segundos.
- Los correos y originales EML se guardan en almacenamiento privado, no en Git.
- Duplicados relacionados y excluidos de las estadísticas.
- Bloqueo y liberación requieren validación, responsable y justificación.
- Copia de correos y originales a PostgreSQL mediante GitHub Actions cada 5 minutos aproximadamente; consulta [la integración](postgres/SINCRONIZACION.txt). La web continúa leyendo Sites.

## Web en GitHub Pages

https://paauuferreer.github.io/HACKATON_g2/

Backend privado: https://hackapol-soc-equipo-dos.sampol-1496.chatgpt.site

El acceso sigue siendo privado. Publicar el código aquí no abre acceso a los datos.
El archivo `.openai/hosting.json` identifica el proyecto existente de Sites.
Cada push a main publica la interfaz en GitHub Pages mediante GitHub Actions. El backend privado se despliega por separado en Sites.

## Desarrollo y pruebas

Node >=22.13, Git y npm.

```sh
npm ci
npm run dev
node node_modules/typescript/bin/tsc --noEmit
node --import tsx --test tests/soc.test.mjs tests/ingestion.test.mjs tests/service.test.ts
npm run build
```

## API de bloqueos del equipo 2

Base: https://hackathon-api-a6ckg4g2ejg4cda4.francecentral-01.azurewebsites.net

- `POST /equipo-2/bloquear`
- `POST /equipo-2/liberar`
- `GET /equipo-2/bloqueos` para comprobar el resultado.
- Cabecera `X-API-Key`, tomada del secreto de servidor `BLOCK_API_KEY`.
- Cuerpo con un único objetivo: `{"ip":"192.0.2.10"}` o `{"usuario":"cuenta"}`.

La aplicación extrae IPv4 y cuentas de correo; no ejecuta contención al recibir
un mensaje. No reintenta automáticamente los POST de contención.
La clave ya está configurada como secreto en Sites. Consulta de lectura verificada con HTTP 200 el 03/11/2026. No se incluyen credenciales en Git ni se han ejecutado bloqueos reales.

## Outlook y Power Automate

Conexión Office 365 Outlook: al llegar un correo, exportar EML y enviar a
`POST /api/power-automate`. Contrato de cuerpo en `docs/power-automate-body.json`.
La credencial privada del receptor se configura en el flujo con entradas y salidas
protegidas, nunca en el repositorio. La frecuencia de 10 segundos corresponde a
la consulta de la web; el conector Outlook puede añadir latencia.

## Variables de Sites

`INGEST_MODE=power-automate`, `OUTLOOK_MAILBOX`, `SOC_SENDERS`, `APPROVER_EMAILS`.
Secretos: `BLOCK_API_KEY` y `POWER_AUTOMATE_SERVICE_TOKEN`.
PostgreSQL opcional: `SOC_BACKEND_URL` (HTTPS), `SOC_BACKEND_TOKEN` (secreto).
Los secretos se configuran en el entorno de ejecución, no en el navegador ni Git.

## PostgreSQL

Esquema: `postgres/schema.sql`. Servicio: `postgres/server.ts`.
Copiar `postgres/.env.example` a `postgres/.env`, configurar y ejecutar:

```sh
npm run start:postgres
```

Ver `docs/INTEGRACION-POSTGRESQL.txt`; sus rutas `app/` corresponden a la raíz
de este repositorio. La conexión real y la migración del almacenamiento provisional
requieren coordinarse con el responsable de la base de datos.

## Alcance

Reglas explicables y revisión humana; no certificación INCIBE. Los adjuntos
binarios se conservan en EML y requieren análisis manual. La importación histórica
inicial está limitada a 1.000 mensajes de Inbox. No se han ejecutado bloqueos reales.



## Conectar la sesión desde GitHub Pages

1. Abrir https://paauuferreer.github.io/HACKATON_g2/.
2. Pulsar **Conectar sesión privada**. Permitir la ventana emergente.
3. En la ventana privada, iniciar sesión si hace falta y pulsar **Conectar mi panel de GitHub**.
4. Mantener esa ventana abierta y volver al panel de GitHub Pages.

GitHub Pages solo sirve HTML, CSS y JavaScript. El backend permanece en Sites:
recibe Power Automate, guarda datos privados y llama a la API con su secreto.
El panel se comunica mediante postMessage con la ventana autenticada, que solo
acepta el origen exacto `https://paauuferreer.github.io`, su ventana de apertura
y un identificador de sesión. La sesión requiere confirmación explícita.
No hay claves en el navegador de GitHub ni datos de correo en los archivos públicos.
Las operaciones mantienen la autorización y validación del backend. Las peticiones
para mostrar credenciales están bloqueadas en esta conexión. No se reintenta un POST.

Para desarrollo estático: `npm run build:pages` genera `dist-pages/`.
El despliegue usa `.github/workflows/pages.yml`; no necesita secretos de la API en Actions.
Si se cierra la ventana privada, volver a conectar la sesión. Si un inicio de sesión
separa las ventanas, cerrar la ventana privada y volver a pulsar Conectar en el panel.
