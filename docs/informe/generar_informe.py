"""
Construye docs/informe/INFORME.md y docs/informe/web.json a partir de datos.json (generar_datos.py) y evidencias.md.

Uso (desde la raíz del repo):
    .venv/bin/python docs/informe/generar_datos.py && .venv/bin/python docs/informe/generar_informe.py

Cada cifra económica lleva su origen: [D] dato del director (Excel), [BD] base de datos del equipo, [H] hipótesis nuestra.
"""
import json
from pathlib import Path

DIR = Path(__file__).resolve().parent
d = json.loads((DIR / "datos.json").read_text(encoding="utf-8"))
evidencias = (DIR / "evidencias.md").read_text(encoding="utf-8")
hip = d.get("excel", {}).get("hipotesis", {})


def num(celda, defecto):
    v = hip.get(celda, defecto)
    return v if isinstance(v, (int, float)) else defecto


def eur(x):
    return f"{x:,.0f} €".replace(",", ".")


ESC = ["Bajo", "Medio", "Alto"]           # escenarios de coste (de menos a más grave)
COL = ["B", "C", "D"]                      # columnas del Excel (prudente, realista, optimista)

# ---- Datos del director [D]
H_ANALISTA = num("C8", 45)
H_DESARROLLO = num("C18", 50)
H_PARADA = num("C25", 25000)
ALERTAS_MES = num("C6", 3000)
MIN_ALERTA = num("C7", 12)
BLOQ_MES = num("C9", 120)
MIN_BLOQ = num("C10", 25)
HORAS_PARADA = [num(c + "24", h) for c, h in zip(COL, (2, 4, 8))]   # horas de parada por incidente grave

# ---- Cadena de ransomware [BD]
victimas = d["cadena_victimas"]
n_vict = len(victimas)
sedes = sorted({s.strip() for v in victimas for s in (v["sedes"] or "").split(",") if s.strip()})
n_sedes = len(sedes)
en_impacto = [v for v in victimas if (v["fase_maxima"] or "").startswith("Impacto")]
tempranas = [v for v in victimas if v["min_ganados"]]
min_ganados = [int(v["min_ganados"]) for v in tempranas]
SERVIDORES_LAB = 4   # LAB-FS-01, LAB-APP-04, LAB-BKP-02, LAB-WS-17 (correos del director)

# ---- Hipótesis de impacto [H]
H_RESP_POR_EQUIPO = [8, 12, 20]       # horas de analista por equipo comprometido
H_REST_POR_EQUIPO = [6, 10, 16]       # horas de restauración por equipo
H_REST_POR_SERVIDOR = [16, 24, 40]    # horas por servidor LAB afectado
EXTERNOS = [15000, 30000, 60000]      # forense externo + asesoría jurídica
COMUNICACION = [5000, 15000, 40000]   # notificaciones y comunicación a afectados
EFECTIVIDAD_AUTO06 = [0.5, 0.7, 0.9]  # parte del impacto evitado si se bloquea al detectar el compromiso

coste = []
for i in range(3):
    parada = n_sedes * HORAS_PARADA[i] * H_PARADA
    respuesta = n_vict * H_RESP_POR_EQUIPO[i] * H_ANALISTA
    restauracion = (n_vict * H_REST_POR_EQUIPO[i] + SERVIDORES_LAB * H_REST_POR_SERVIDOR[i]) * H_DESARROLLO
    total = parada + respuesta + restauracion + EXTERNOS[i] + COMUNICACION[i]
    evitado = (len(tempranas) / n_vict if n_vict else 0) * parada * EFECTIVIDAD_AUTO06[i]
    coste.append({"escenario": ESC[i], "horas_parada": HORAS_PARADA[i], "parada": parada, "respuesta": respuesta,
                  "restauracion": restauracion, "externos": EXTERNOS[i], "comunicacion": COMUNICACION[i],
                  "total": total, "evitado_auto06": evitado})

# ---- SOC manual y ROI [D] + ruido real [BD]
coste_alertas = ALERTAS_MES * MIN_ALERTA / 60 * H_ANALISTA
coste_bloqueos = BLOQ_MES * MIN_BLOQ / 60 * H_ANALISTA
coste_soc_mes = coste_alertas + coste_bloqueos
ruido_real = d["ruido_real"]["pct"]
# Escenario realista del Excel recalculado con el ruido real de la BD
filtrado, min_con, pct_cont = num("C13", 0.75), num("C14", 6), num("C15", 0.7)
restantes = ALERTAS_MES - ALERTAS_MES * ruido_real * filtrado
ahorro_alertas = coste_alertas - restantes * min_con / 60 * H_ANALISTA
ahorro_bloq = BLOQ_MES * num("C34", 0.5) * (MIN_BLOQ - num("C35", 3)) / 60 * H_ANALISTA
recurrentes = num("C19", 40) + num("C20", 100) + num("C21", 10) * H_ANALISTA
inversion = num("C17", 240) * H_DESARROLLO
neto_mes_real = (ahorro_alertas + ahorro_bloq) * pct_cont - recurrentes
roi_real = {"ruido_real": ruido_real, "ahorro_neto_mes": neto_mes_real, "inversion": inversion,
            "recuperacion_meses": inversion / neto_mes_real if neto_mes_real > 0 else None,
            "roi_1": ((neto_mes_real + recurrentes) * 12 - (inversion + 12 * recurrentes)) / (inversion + 12 * recurrentes)}
franjas = d["por_franja"]
total_alertas = sum(f["total"] for f in franjas) or 1
noche = next((f for f in franjas if f["franja"] == "GUARDIA_NOCHE"), {"total": 0, "criticas": 0})

web = {"generado": d["generado"], "kpis": d["kpis"], "ruido": d["ruido_real"], "coste": coste,
       "soc": {"alertas_mes": ALERTAS_MES, "min_alerta": MIN_ALERTA, "coste_hora": H_ANALISTA,
               "coste_mes": coste_soc_mes, "pct_noche": noche["total"] / total_alertas},
       "roi_real": roi_real, "victimas": victimas, "fases": d["cadena_fases"], "ips": d["ips_reconstruidas"],
       "prediccion": d["prediccion"], "acciones": d["acciones"], "otros": d["otros_casos"],
       "aislados": d["compromisos_aislados"], "franjas": franjas, "sedes": d["por_sede"], "clases": d["por_clase"],
       "outlook": d["outlook"], "parada_hora": H_PARADA, "n_sedes": n_sedes, "sedes_lista": sedes,
       "min_ganados": min_ganados}
(DIR / "web.json").write_text(json.dumps(web, ensure_ascii=False, indent=1), encoding="utf-8")

# ---------------------------------------------------------------- INFORME.md
k = d["kpis"]
medio = coste[1]
L = []
w = L.append
w("# Informe final · Equipo 2 · Reto SOC Sampol (Hackathon FP 2027)")
w(f"\n*Generado el {d['generado']} (hora de Madrid) a partir de la base de datos del equipo, el buzón del reto y "
  f"el análisis económico. Origen de cada cifra: **[D]** dato del director · **[BD]** base de datos · **[H]** hipótesis del equipo.*\n")

w("## 1. Resumen ejecutivo")
w(f"- **Qué ha pasado.** Una intrusión ha saltado de cuenta en cuenta: **{n_vict} cuentas `*moreno`** en "
  f"**{n_vict} equipos de {n_sedes} sedes** ({', '.join(sedes)}), una nueva cada ~{int(d['prediccion'].get('min_medios_entre_avisos') or 0)} min. "
  f"Todas llegan a la fase de impacto: ficheros alterados o perdidos. En paralelo, el director informa de un ransomware con "
  f"**doble extorsión**, **18 GB enviados a una IP externa**, copias de seguridad debilitadas y un **documento de pagos manipulado**.")
w(f"- **Cuánto puede costar.** Entre **{eur(coste[0]['total'])}** y **{eur(coste[2]['total'])}** "
  f"(escenario medio: **{eur(medio['total'])}**). Lo que más pesa es la parada del servicio, a {eur(H_PARADA)}/h [D]. "
  f"A eso se suman una posible sanción (hasta el 4 % de la facturación o 20 M€ por el RGPD) y el fraude en pagos, cuyo importe está pendiente.")
w(f"- **Qué hemos construido.**")
w(f"  - **Base de datos:** recibe el buzón, clasifica las alertas con la taxonomía INCIBE y detecta duplicados, inconsistencias y correos manipulados ({k['correos_recibidos']} correos procesados).")
w(f"  - **Bloqueo automático:** AUTO-05 bloquea con alerta crítica verificada. AUTO-06 bloquea por correlación al detectar la cuenta comprometida, **{min(min_ganados) if min_ganados else 0}-{max(min_ganados) if min_ganados else 0} min antes** de la primera alerta crítica, con 0 falsos positivos.")
w(f"  - **Valor económico:** solo el coste evitado gracias a AUTO-06 se estima en **{eur(medio['evitado_auto06'])}** en el escenario medio [H].")
w(f"- **Qué no ha funcionado.** La clave de la API de bloqueo fue revocada (401) tras intentar reenviarse la ficha de credenciales a una cuenta externa: "
  f"hay **{sum(1 for a in d['acciones'] if a['estado'] == 'PENDIENTE')} bloqueos en cola y 0 ejecutados**. Además, dos directrices siguen sin responder.")

w("\n## 2. Qué hicimos durante el reto (cronología)")
w("| Hora | Hito |\n|---|---|")
for hora, hito in [
    ("03/11 mañana", "Lectura del reto, conexión con PostgreSQL de Azure y con la API; esquema 001-004 (bandeja inmutable, alertas, taxonomía INCIBE, 39 reglas)"),
    ("03/11 tarde", "Ingesta del buzón (Power Automate → Sites → GitHub Actions → BD); panel web del equipo; organización con contrato de BD y buzón de coordinación"),
    ("03/11 18:00-20:00", "Directriz del director: automatizar bloqueos → migraciones 005-006 (bloqueo de nivel 2 y analítica por franjas)"),
    ("03/11 21:30-23:00", "Diagnóstico: 0 bloqueos posibles, extracción rota y API en 401 → migraciones 007 (extracción HTML), 008-010 (autenticidad por cabeceras de Exchange, regla AUTO-05)"),
    ("03/11 23:00-00:00", "Investigación: cadena *moreno → migraciones 011-013 (fases del ataque, AUTO-06, corrección de corroboración); línea temporal para el jurado"),
    ("04/11 madrugada", "Organización de Outlook (011 del compañero + 015/016), carpetas y flujo de Power Automate; respuestas a las directrices de crisis del director"),
]:
    w(f"| {hora} | {hito} |")
w(f"\nMigraciones aplicadas en Azure: {len({m['version'][:3] for m in d['migraciones']})} (001-{max(m['version'][:3] for m in d['migraciones'])}; "
  f"{len(d['migraciones'])} registros, porque 3 se renumeraron al llegar la organización de Outlook).")

w("\n## 3. Costes para la empresa")
w("### 3.1 Impacto del ransomware (por sede y equipo afectados)")
w(f"Base: **{n_sedes} sedes** y **{n_vict} equipos** en fase de impacto [BD], más {SERVIDORES_LAB} servidores LAB citados por el director "
  f"(LAB-FS-01, LAB-APP-04, LAB-BKP-02, LAB-WS-17). Hora de servicio parado: {eur(H_PARADA)}/h [D]; analista {eur(H_ANALISTA)}/h [D]; "
  f"técnico {eur(H_DESARROLLO)}/h [D].\n")
w("| Concepto | " + " | ".join(c["escenario"] for c in coste) + " | Origen |\n|---|---|---|---|---|")
filas = [("Horas de parada por sede", "horas_parada", "[D] horas del Excel"),
         ("Parada del servicio (sedes × horas × 25.000 €)", "parada", "[D]+[BD]"),
         ("Respuesta (analistas por equipo comprometido)", "respuesta", "[H] 8/12/20 h por equipo"),
         ("Restauración (equipos + servidores LAB)", "restauracion", "[H] 6/10/16 h y 16/24/40 h"),
         ("Forense externo y asesoría jurídica", "externos", "[H]"),
         ("Notificación y comunicación a afectados", "comunicacion", "[H]"),
         ("**Total estimado**", "total", "")]
for nombre, clave, origen in filas:
    vals = [f"{c[clave]:g} h" if clave == "horas_parada" else eur(c[clave]) for c in coste]
    if clave == "total":
        vals = [f"**{v}**" for v in vals]
    w(f"| {nombre} | " + " | ".join(vals) + f" | {origen} |")
w("\n**No incluido (exposición sin cuantificar):**")
w("- **Fraude en pagos:** documento con la cuenta de destino cambiada (alerta AL-20261030-0121 y correo del director de las 3:46); el importe es desconocido.")
w("- **Rescate:** doble exigencia, no se recomienda pagar.")
w("- **Sanciones:** RGPD art. 83.5, hasta 20 M€ o el 4 % de la facturación anual; NIS2 art. 34, hasta 10 M€ o el 2 % para entidades esenciales del sector energético.")
w("- **Daño reputacional y pérdida de contratos.**")

w("\n### 3.2 Coste evitado con la detección temprana (AUTO-06)")
w(f"En {len(tempranas)} de las {n_vict} víctimas (vía robo de credenciales), AUTO-06 detecta la cuenta comprometida "
  f"**entre {min(min_ganados) if min_ganados else 0} y {max(min_ganados) if min_ganados else 0} min antes** que la primera alerta crítica [BD]. "
  f"Si el bloqueo se hubiera ejecutado entonces, se habría evitado la parada de esa parte de la cadena con una efectividad del 50/70/90 % [H]:\n")
w("| | " + " | ".join(c["escenario"] for c in coste) + " |\n|---|---|---|---|")
w("| Coste evitado estimado | " + " | ".join(eur(c["evitado_auto06"]) for c in coste) + " |")

w("\n### 3.3 Coste del SOC manual")
w(f"- {int(ALERTAS_MES)} alertas al mes × {int(MIN_ALERTA)} min × {eur(H_ANALISTA)}/h [D] = **{eur(coste_alertas)}/mes**; "
  f"bloqueos manuales {int(BLOQ_MES)} × {int(MIN_BLOQ)} min = {eur(coste_bloqueos)}/mes. **Total: {eur(coste_soc_mes)}/mes ({eur(coste_soc_mes*12)}/año).**")
w(f"- En el buzón real, el **{noche['total']/total_alertas:.0%} de las alertas llega en guardia de noche** (22:00-08:00), "
  f"con {noche['criticas']} críticas [BD]. Es la franja más cara y la que tiene menos personal.")
w(f"- Ruido real medido: **{ruido_real:.1%}** de los correos ({d['ruido_real']['ruido']} de {d['ruido_real']['correos']}: duplicados, informativos, "
  f"no SOC y malformados) [BD]. El Excel supone entre el 55 % y el 70 %.")

w("\n### 3.4 Retorno de nuestra solución")
w("| Indicador | Excel (realista) | Recalculado con el ruido real |\n|---|---|---|")
calc = d.get("excel", {}).get("calculos", {})
w(f"| Ahorro neto mensual | {calc.get('C26', '13.806 €')} | {eur(roi_real['ahorro_neto_mes'])} |")
w(f"| Inversión inicial | {calc.get('C24', '12.000 €')} | {eur(roi_real['inversion'])} |")
rec = roi_real["recuperacion_meses"]
w(f"| Periodo de recuperación | {calc.get('C28', '0,9')} meses | {rec:.1f} meses |" if rec else "| Periodo de recuperación | — | no se recupera |")
w(f"| ROI del primer año (solo tiempo) | {calc.get('C31', '805 %')} | {roi_real['roi_1']:.0%} |")
w("\nIncluso con el ruido real, que es menor, la solución propia se recupera en semanas. "
  "A 3 años sale mejor que un SIEM/SOAR comercial (60.000 €/año + 20.000 € de implantación [D]); ver la hoja «Comparativa» del Excel. "
  "Las horas liberadas se reasignan a investigación, no a reducir plantilla.")

w("\n## 4. Análisis forense")
w("### 4.1 La cadena *moreno")
p = d["prediccion"]
nuevas = sorted({a['usuario_objetivo'] for a in d['acciones'] if a['usuario_objetivo'] and a['estado'] == 'PENDIENTE'} - {v['victima'] for v in victimas} - {'qgomez@sampol.com'})
w(f"- **Origen conocido:** jmoreno@sampol.com (srv-barcelona-201). Un correo con formulario falso → fuerza bruta → acceso no reconocido.")
w(f"- **Propagación:** una cuenta y un equipo nuevos cada ~{int(p.get('min_medios_entre_avisos') or 0)} min de aviso; numeración de equipos consecutiva "
  f"(201 → {200 + n_vict}); sedes en rotación ({', '.join(sedes)}).")
w("- **Dos vías de entrada que se alternan:**")
w("  - Robo de credenciales: phishing → fuerza bruta → acceso no reconocido → lectura → mando y control → impacto.")
w("  - Explotación del equipo: sondeo de puertos → petición con explotación → proceso anómalo → mando y control → impacto.")
w(f"- **Siguiente víctima estimada:** hacia las {str(p.get('siguiente_victima_estimada_aviso', ''))[11:16]} (hora de aviso). "
  f"Ya en cola automáticamente y sin cadena completa todavía: {', '.join(nuevas) or 'ninguna'}.\n")
w("| # | Cuenta | Equipo | Sede | IP relacionada | Primer aviso | Fases | Fase máxima | Detección temprana | Bloqueo |\n|---|---|---|---|---|---|---|---|---|---|")
for v in victimas:
    ip = ", ".join(d["ips_reconstruidas"].get(v["victima"], [])) or (v["ips"] or "—")
    temprana = f"+{int(v['min_ganados'])} min" if v["min_ganados"] else "— (vía explotación)"
    w(f"| {v['orden_victima']} | {v['victima']} | {v['equipos']} | {v['sedes']} | {ip} | {v['primer_aviso']} | {v['num_fases']} | "
      f"{v['fase_maxima']} | {temprana} | {v['estado_bloqueo'] or '—'} ({v['origen_bloqueo'] or '—'}) |")
w("\n*Las IPs sin puntos del correo original (p. ej. `2030113150`) se han reconstruido como 203.0.113.150. Todas pertenecen a rangos de documentación (TEST-NET).*")

w("\n### 4.2 Indicadores y hechos del incidente (correos del director)")
for linea in [
    "**LAB-FS-01**: archivos `.locked` y nota de rescate (1:05).",
    "**LAB-WS-17**: sesión activa contra LAB-FS-01; desfase horario de 11 min (1:21, 2:25).",
    "**LAB-APP-04**: 18 GB hacia **198.51.100.77**, `auditoria_2026.7z`, tarea «System Health Check» y herramienta remota sin validar (1:53, 2:41).",
    "**LAB-BKP-02**: retención de copias reducida; la identidad investigada tenía permisos (2:57).",
    "`ejercicio.backup`: escrituras fuera de su origen habitual (1:21, 2:25).",
    "Doble extorsión: descifrado y no publicación; muestra con la marca «Escenario ficticio» y un dominio `.invalid` (1:37, 3:13).",
    "Hipótesis de acceso inicial del director: soporte remoto no validado, credenciales expuestas o archivo por correo (4:34).",
]:
    w(f"- {linea}")

w("\n### 4.3 Otros casos relevantes")
w("| Alerta | Cuenta | Equipo | Gravedad | Hecho | Aviso |\n|---|---|---|---|---|---|")
for o in d["otros_casos"]:
    w(f"| {o['id_alerta_soc']} | {o['usuario']} | {o['equipo'] or '—'} | {o['gravedad']} | {o['titulo']} | {o['aviso']} |")
w(f"\n**Compromisos aislados, sin cadena previa** (AUTO-06 los descarta y quedan para revisión humana): {', '.join(c['usuario'] for c in d['compromisos_aislados'])}.")
w("\n**Incidente interno:** el 03/11 a las 12:30, la cuenta del equipo intentó reenviar la ficha de credenciales a una Gmail personal. "
  "La regla de transporte lo bloqueó, pero la clave de la API acabó revocada (ver anexo de evidencias).")

w("\n### 4.4 Impacto para la empresa")
w(f"- **Disponibilidad:** {n_vict} equipos y servidores de ficheros, aplicaciones y copias comprometidos en {n_sedes} sedes; reapertura condicionada a identidades verificadas.")
w("- **Confidencialidad:** posible extracción (18 GB) de contratos, información financiera y expedientes de personal, propios y de terceros. Obliga a valorar notificar en 72 h (RGPD).")
w("- **Integridad:** documento de pagos alterado y copias con retención reducida. No hay RTO/RPO acordados.")
w("- **Recuperabilidad:** sin una restauración reciente probada; las copias no son fiables hasta validarlas en un entorno aislado.")

w("\n## 5. Respuesta y controles implantados")
acc = d["acciones"]
w(f"- **Bloqueo automático (BD):** AUTO-05 (crítico verificado) y AUTO-06 (correlación). Decisiones: "
  + ", ".join(f"{x['regla_id']} {x['decision']} {x['tipo_objetivo']}={x['total']}" for x in d["decisiones"]) + ".")
w(f"- **Cola de bloqueos:** {sum(1 for a in acc if a['estado']=='PENDIENTE')} pendientes, "
  f"{sum(1 for a in acc if a['estado']=='OMITIDA')} omitida (falso positivo corregido) y 0 ejecutados (API en 401).")
w("- **Autenticidad del remitente:** SPF pass de protection.outlook.com, AuthAs Internal y SHA-256 del original. Las directrices solo valen de dirti@.")
w("- **Buzón:** 10 carpetas y un flujo de Power Automate que ordena cada correo nuevo 5 min después de que lo capture la ingesta.")
w("- **Directrices de crisis:** respondidas la mayoría; «Solicitud externa no verificada» solo con acuse y «Criterios de reapertura» y «Análisis de la causa inicial» sin responder (ver anexo A).")

w("\n## 6. Lo que no salió bien y lecciones aprendidas")
for problema, leccion in [
    ("La ficha con credenciales se intentó reenviar a una Gmail desde la cuenta del equipo; la API se revocó", "Las credenciales solo en `.env` y gestores de secretos; nunca reenviar fichas. Tratar cualquier exposición como un compromiso y pedir rotación por un canal seguro"),
    ("0 bloqueos ejecutados: 13 decisiones correctas quedaron en cola", "Tener una vía alternativa para contener (manual con registro) y vigilar la salud de la API (401) con una alarma"),
    ("La extracción de campos estaba rota (usuario «relacionada» en 110/110) hasta la migración 007", "Probar con correos reales desde el principio, no solo con datos sintéticos"),
    ("La corroboración contaba los reenvíos como alertas nuevas (falso positivo de slopez)", "Contar por identificador de alerta; las pruebas de regresión antes de activar reglas que bloquean"),
    ("La ingesta dependía de un cron de GitHub que no se ejecutaba solo", "Ingesta directa de Power Automate a la BD y monitorizar el retraso (último correo recibido)"),
    ("El inicio de sesión de Graph falló; no había conexión de PostgreSQL en Power Automate", "Validar antes del evento las licencias, conectores y permisos (Mail.ReadWrite, Premium)"),
    ("Error de operación en Outlook: «Copiar» en lugar de «Mover» (30 copias)", "Confirmar la acción antes de las operaciones masivas; preferir la automatización revisable a los clics masivos"),
    ("Directrices con plazos de 10/20 min y equipo saturado: 2 sin responder", "Reparto de guardias y plantillas de acuse; un responsable de comunicación con dirección"),
]:
    w(f"- **{problema}.** → {leccion}.")

w("\n## 7. Recomendaciones y próximos pasos")
for r in [
    "Rotar la clave de la API por un canal seguro y ejecutar la cola de bloqueos con verificación (GET) y registro.",
    "Aislar LAB-APP-04, LAB-WS-17 y LAB-FS-01 conservando las evidencias; revocar las sesiones y credenciales de las cuentas *moreno.",
    "Restaurar en un entorno aislado desde copias anteriores al compromiso; acordar RTO/RPO por servicio.",
    "Bloquear la IP 198.51.100.77 y las IPs de la cadena tras revisión humana (las IPs no se bloquean solas).",
    "Verificar con el banco el pago desviado y congelar los cambios de datos maestros de proveedores.",
    "Jurídico y protección de datos: decidir sobre la notificación (72 h) y la comunicación a afectados con hechos verificados.",
    "Mejoras de prioridad alta del Excel (6.100 €): plantillas de notificación, lista blanca y aprobación, clasificación INCIBE y detección de phishing.",
]:
    w(f"- {r}")

w("\n## Anexo A · Evidencias del buzón\n")
w(evidencias.split("\n", 2)[2] if evidencias.startswith("#") else evidencias)
w("\n## Anexo B · Metodología y fuentes")
w("- Base de datos del equipo: vistas `v_kpis`, `v_cadena_victimas`, `v_cadena_ransomware`, `v_decisiones_bloqueo`, `v_stats_franja`, entre otras (`db/schema.sql`).")
w("- Análisis económico: `Analisis_economico_Sampol.xlsx` (datos del director en verde; hipótesis en amarillo).")
w("- Sanciones: Reglamento (UE) 2016/679, art. 83; Directiva (UE) 2022/2555 (NIS2), art. 34.")
w("- El informe se regenera con `docs/informe/generar_datos.py` y `docs/informe/generar_informe.py`.")

(DIR / "INFORME.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print(f"INFORME.md ({len(L)} líneas) y web.json. Coste medio {eur(medio['total'])}; evitado AUTO-06 {eur(medio['evitado_auto06'])}")

# ---------------------------------------------------------------- Infografía web (Artifact)
plantilla = (DIR / "plantilla_web.html").read_text(encoding="utf-8")
datos_web = json.dumps(web, ensure_ascii=False).replace("</", "<\\/")
(DIR / "informe_web.html").write_text(plantilla.replace("__DATA__", datos_web), encoding="utf-8")
print("informe_web.html listo")
