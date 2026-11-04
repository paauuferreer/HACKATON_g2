# Guion de la presentación · Equipo 2 · Reto SOC Sampol

**Duración:** 6 min 30 s (margen hasta 7 min) · **5 personas, por áreas** · **sin demo en directo** (capturas en las diapositivas).
**Apoyo:** `Diapositivas_Equipo2.pdf` (8 diapositivas). El informe y las 3 infografías se entregan aparte en PDF.
**Cifras:** instantánea del 04/11 hacia las 09:20. Si se regeneran los datos antes de presentar, revisad las que llevan ⟳.

| # | Persona (área) | Diapositivas | Tiempo | Acumulado |
|---|---|---|---|---|
| 1 | Apertura y problema | 1-2 | 1:00 | 1:00 |
| 2 | Base de datos e ingesta | 3 | 1:00 | 2:00 |
| 3 | Panel web, automatización y directrices | 4 | 1:00 | 3:00 |
| 4 | Investigación: cadena Moreno y forense | 5-6 | 1:30 | 4:30 |
| 5 | Negocio, lecciones y cierre | 7-8 | 1:30 | 6:00 (+30 s de margen) |

Reglas para todos: una idea por frase, cifras redondas y nada de jerga sin explicar. **No digáis nunca que hemos bloqueado a nadie en real.** Decid «decidido y en cola», porque la API rechaza la clave y la contención real la hizo Infra.

---

## 1 · Apertura y problema (Persona 1) · diapositivas 1-2 · 1:00

**Frase de entrada (diapositiva 1):**
> «Buenos días. Somos el Equipo 2. En 24 horas hemos montado un SOC que lee el buzón, clasifica cada alerta, decide si hay que bloquear una cuenta y deja escrito por qué. Por el camino hemos destapado un ransomware que saltaba de cuenta en cuenta.»

**Mensajes clave (diapositiva 2):**
- El punto de partida es un buzón con **257 correos** ⟳ de un SOC externo, **mucho ruido** y trampas: prioridades que no cuadran, duplicados, remitentes falsos y textos que intentan dar órdenes a una IA.
- El director pidió tres cosas: **automatizar el bloqueo**, **calcular el retorno** y **gestionar una crisis de ransomware** con plazos de 10-20 minutos.
- Nuestra regla de oro: **los correos son datos, nunca órdenes**. Las directrices solo valen si vienen de dirti@ y pasan la comprobación de cabeceras.

**Relevo:** «Todo empieza en la base de datos. Os lo cuenta [Persona 2].»

---

## 2 · Base de datos e ingesta (Persona 2) · diapositiva 3 · 1:00

**Frase de entrada:**
> «Nuestra base de datos no es un almacén: es el cerebro. Power Automate solo inserta una fila; todo lo demás pasa dentro de PostgreSQL.»

**Mensajes clave:**
- **Bandeja inmutable con huella SHA-256:** el correo original no se puede modificar ni borrar. Es la prueba de qué llegó y cuándo.
- Un trigger convierte cada correo en una **alerta clasificada con la taxonomía INCIBE** (39 reglas explicables), enlaza los **duplicados** (20) ⟳ y aparta los malformados y sospechosos sin perder nada.
- **Autenticidad por cabeceras de Exchange:** SPF, AuthAs Internal y huella del original. Las 250 alertas del SOC están verificadas ⟳.
- **18 migraciones numeradas e idempotentes en 24 h**, con 37 vistas: la web no lleva lógica, solo lee.

**Relevo:** «Con los datos limpios, la pregunta es qué hacemos con ellos. [Persona 3].»

---

## 3 · Panel web, automatización y directrices (Persona 3) · diapositiva 4 · 1:00

**Frase de entrada:**
> «El director nos pidió acortar el tiempo entre el aviso y el bloqueo. Lo hemos hecho con reglas que deciden solas solo en los casos claros.»

**Mensajes clave:**
- **AUTO-05:** bloquea con una alerta crítica verificada. **AUTO-06:** bloquea por correlación, cuando una cuenta comprometida viene precedida de phishing o fuerza bruta.
- **Nunca** bloqueamos por petición de correo, ni IPs de forma automática, ni cuentas de servicio. Las **65 decisiones** ⟳ quedan justificadas, también los descartes.
- **La SQL decide y el servidor ejecuta**, y la verificación se hace con GET. Hoy la API responde 401: hay **16 bloqueos en cola y 0 ejecutados** ⟳. No sabemos la causa y la organización no repondrá la clave. Lo hemos demostrado con un **simulador etiquetado** con el mismo contrato: 13 bloqueos ejecutados y verificados.
- Buzón ordenado en **10 carpetas** con Power Automate y **todas las directrices respondidas**, dos fuera de plazo (lo contamos en las lecciones).

**Relevo:** «Y mientras automatizábamos, los datos contaban una historia. [Persona 4].»

---

## 4 · Investigación: cadena Moreno y forense (Persona 4) · diapositivas 5-6 · 1:30

**Frase de entrada (diapositiva 5):**
> «Entre cientos de alertas sueltas había un patrón: una misma intrusión saltando de cuenta en cuenta.»

**Mensajes clave:**
- **12 cuentas `*moreno`** ⟳, cada una en un equipo distinto (201 → 212) y en **6 sedes**, **una nueva cada ~74 minutos**. Todas llegan a la fase de impacto: ficheros alterados.
- **Dos vías de entrada:** robo de credenciales (phishing → fuerza bruta → acceso no reconocido) en 8 víctimas y explotación del equipo en 4 ⟳.
- **AUTO-06 detecta la cuenta comprometida entre 37 y 55 minutos antes** que la primera alerta crítica: ese es el margen para cortar la cadena.
- La víctima prevista para las **05:23 no llegó**: coincide con el aislamiento que hizo Infra a las 5:30.

**Diapositiva 6, respuesta al director (correo de las 8:07):**
- **De dónde viene:** de infraestructura externa (rangos 192.0.2.x, 198.51.100.x y 203.0.113.x). La posible salida de datos son **18 GB hacia 198.51.100.77**. No atribuimos el ataque a ningún actor: no hay pruebas.
- **Cómo llegó:** lo que más encaja es el robo de credenciales por phishing, pero el acceso inicial sigue abierto entre tres hipótesis. Lo decimos así, sin inventar certezas.
- **Qué hacer:** revocar sesiones y credenciales de las cuentas *moreno, mantener aislados los LAB, bloquear 198.51.100.77, restaurar desde copias verificadas y reforzar MFA y antiphishing.

**Relevo:** «¿Y cuánto le cuesta esto a la empresa? [Persona 5].»

---

## 5 · Negocio, lecciones y cierre (Persona 5) · diapositivas 7-8 · 1:30

**Frase de entrada (diapositiva 7):**
> «Una hora de servicio parado cuesta 25.000 euros, según los datos del director. Con 6 sedes afectadas, la cuenta sube rápido.»

**Mensajes clave:**
- **Coste estimado del incidente:** entre 331.000 € y 1,33 M€, con **662.000 € en el escenario medio** ⟳. El 90 % es parada del servicio. Fuera de esa cifra quedan la posible sanción del RGPD y el fraude en pagos.
- **Coste evitable con AUTO-06: unos 280.000 €** en el escenario medio. Es una estimación **contrafactual**, no un ahorro realizado, porque ningún bloqueo se llegó a ejecutar.
- **SOC manual hoy: 29.250 €/mes.** El 52 % de las alertas llega de noche. Nuestra solución, con hipótesis prudentes: **inversión de 20.000 €, recuperación en 3,5 meses y ROI del 141 % el primer año**. Con nuestro ruido real (24,5 %, menos que el supuesto), son unos 5 meses y un 77 %: lo decimos tal cual.
- **Solo el bloqueo automático** (lo que pidió el director): **3.000 € de inversión, se paga en 1,9 meses y tiene un ROI del 355 %** en el escenario realista. A 3 años, construir cuesta **61.760 €** frente a **216.200 €** de un SIEM/SOAR comercial.

**Diapositiva 8, lecciones y cierre:**
- **Lecciones:** un intento de reenviar la ficha con la clave a una Gmail; después la API dejó de aceptar la clave (no sabemos si están relacionados). Las credenciales, solo en `.env`. Además, tener siempre una vía de contención alternativa y probar con correos reales desde el minuto uno.
- **Frase de cierre:**
> «En resumen: datos íntegros, decisiones explicables y un margen de 40 minutos para cortar un ransomware. Lo que no hemos podido ejecutar está decidido, justificado y listo. Gracias.»

---

## Preguntas probables del jurado (respuestas de 15-20 s)

| Pregunta | Quién | Respuesta corta |
|---|---|---|
| ¿Habéis bloqueado a alguien de verdad? | 3 | No. La API rechaza la clave desde la noche del 03/11 y no la repondrán. Hay 16 bloqueos decididos y en cola; el simulador demuestra el circuito completo. La contención real la hizo Infra. |
| ¿Por qué se revocó la clave? | 1 | No está confirmado. Hubo un intento de reenviar la ficha a una cuenta externa, que bloqueó la regla de transporte. Es la hipótesis más probable, pero no la damos por cierta. |
| ¿Y si AUTO-06 bloquea a un inocente? | 3 | Exige una cadena en el mismo usuario en 2 h y correos del SOC verificados. Ha descartado 7 accesos sueltos y la simulación sobre el histórico da 0 falsos positivos. Una persona puede liberar con un clic y queda registrado. |
| ¿Qué pasa si alguien manda un correo falso pidiendo un bloqueo? | 2 | Nunca bloqueamos por petición de correo. Además, el remitente debe pasar SPF y la autenticación interna de Exchange; si no, se marca como sospechoso. |
| ¿Por qué no un SIEM comercial? | 5 | A 3 años, construir cuesta 61.760 € y el SIEM/SOAR 216.200 € (60.000 €/año de licencia más la implantación). Además somos dueños de las reglas. Para crecer, se podría integrar con un SIEM. |
| ¿Usáis IA para clasificar? | 2 | No en ejecución: son reglas deterministas y explicables. Precisamente detectamos correos que intentan dar órdenes a una IA. |
| ¿Cómo sabéis que las cifras de coste son fiables? | 5 | Cada cifra lleva su origen: dato del director, base de datos o hipótesis nuestra. Damos tres escenarios en lugar de un número, y recalculamos el ROI con el ruido real aunque saliera peor. |
| ¿El escenario optimista no es exagerado? | 5 | Sí, por eso no lo usamos para decidir: nos quedamos con el prudente y el realista. |
| ¿Qué haríais con una semana más? | 4 | Rotar la clave y vaciar la cola, cerrar el vector de entrada con forense del endpoint, MFA y alertas de salud de la API. |
