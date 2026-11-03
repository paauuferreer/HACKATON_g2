export const incibeClasses=['Contenido abusivo','Contenido dañino','Obtención de información','Intento de intrusión','Intrusión','Disponibilidad','Compromiso de la información','Fraude','Vulnerable','Otros'];
export const incidentStates=['Nueva','En revisión','Cerrada','Falsa alarma','No es alerta'];
const fold=s=>String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
const rules=[
 ['Contenido dañino',/ransomware|malware|troyano|codigo malicioso|gusano informatico/,'Indicios explícitos de software malicioso.'],
 ['Disponibilidad',/denegacion de servicio|\bddos\b|interrupcion de servicio|sabotaje/,'El efecto principal descrito es la interrupción del servicio.'],
 ['Intrusión',/uso confirmado de cuenta|cuenta.{0,30}comprometida|completo una sesion|inicio correcto.{0,80}(?:no autorizado|niega|global administrator)/,'Se describe uso o compromiso de una cuenta, no solo un intento.'],
 ['Compromiso de la información',/exfiltracion|fuga de datos|perdida de datos|modificacion no autorizada|datos expuestos/,'El hecho principal afecta a la confidencialidad o integridad de información.'],
 ['Fraude',/phishing|suplantacion|fraude|uso no autorizado de recursos/,'Se describe engaño o suplantación.'],
 ['Intento de intrusión',/accesos fallidos|autenticaciones rechazadas|password spray|fuerza bruta|intentos? de (?:acceso|intrusion)|intentos? de explotacion/,'Intentos de acceso o explotación sin compromiso confirmado.'],
 ['Obtención de información',/escaneo|reconocimiento|monitorizacion de trafico|ingenieria social|sniffing/,'Se describen técnicas para recopilar información.'],
 ['Contenido abusivo',/\bspam\b|contenido ofensivo|contenido ilicito/,'Contenido abusivo o no solicitado.'],
 ['Vulnerable',/vulnerabilidad|\bcve-\d|parche pendiente|pendiente de parche|servicio expuesto/,'Debilidad expuesta sin evidencia suficiente de compromiso.'],
];
export function structuredAnalysis(subject,body){
 const plain=String(body).replace(/\*\*|\|/g,' ').replace(/\s+/g,' ');const text=fold(subject+' '+plain);
 const matches=rules.filter(([,pattern])=>pattern.test(text));const picked=matches[0];
 const source=plain.match(/Fuente\s*:?\s*(.{2,80}?)\s+Regla de detecci[oó]n/i)?.[1]?.trim()||plain.match(/Microsoft Entra ID|Microsoft Sentinel|Defender(?: for Endpoint)?|CrowdStrike|Fortinet|Wazuh|Splunk|\bEDR\b/i)?.[0]||'Sin identificar';
 const assets=[...new Set([...plain.matchAll(/\b(?:pc|srv|server|host|fw|dc)-[a-z0-9-]+\b/gi)].map(m=>m[0].toLowerCase()))];
 const relatedUsers=[...new Set([...plain.matchAll(/(?:cuenta(?:\s+(?:privilegiada|relacionada))?|usuario(?:\s+(?:implicado|afectado))?)\s*[:=]?\s*([\w.%+-]+@[\w.-]+\.[a-z]{2,})/gi)].map(m=>m[1].toLowerCase()))];
 const rawDates=[...plain.matchAll(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b/g)].map(m=>m[0]);
 const eventTimeOriginal=rawDates.find(d=>Number.isFinite(Date.parse(d)))||null;
 const severitySource=subject.match(/\[(CR[IÍ]TIC[OA]|ALT[OA]|MEDI[OA]|BAJ[OA])\]/i)?.[1]||plain.match(/Criticidad\s*:?\s*(Cr[ií]tic[oa]|Alta|Media|Baja)/i)?.[1]||'Sin indicar';
 return {incibeClass:picked?.[0]||'Otros',incibeType:null,incibeReason:picked?picked[2]+(matches.length>1?` También hay señales de ${matches.slice(1).map(m=>m[0]).join(', ')}; revisar la clase principal.`:''):'Sin indicadores suficientes; revisión manual necesaria.',incibeCandidates:matches.map(m=>m[0]),classificationReviewed:false,source,assets,relatedUsers,eventTimeOriginal,eventAt:eventTimeOriginal?new Date(eventTimeOriginal).toISOString():null,severitySource,alertId:plain.match(/\bAL-\d{8}-\d+\b/i)?.[0]||null};
}
export function statistics(rows){
 const unique=rows.filter(r=>!r.duplicateOf);const alerts=unique.filter(r=>!['No es alerta','Falsa alarma'].includes(r.status));
 const group=(items,key)=>Object.entries(items.reduce((acc,item)=>{for(const value of key(item)){acc[value]=(acc[value]||0)+1;}return acc;},{})).map(([label,count])=>({label,count})).sort((a,b)=>b.count-a.count);
 return {received:rows.length,uniqueAlerts:alerts.length,duplicates:rows.length-unique.length,needsReview:alerts.filter(r=>r.status!=='Cerrada').length,closed:alerts.filter(r=>r.status==='Cerrada').length,classes:group(alerts,r=>[r.analysis.incibeClass||'Otros']),sources:group(alerts,r=>[r.analysis.source||'Sin identificar']),priorities:group(alerts,r=>[r.analysis.priority]),assets:group(alerts,r=>r.analysis.assets||[]).slice(0,10),users:group(alerts,r=>r.analysis.relatedUsers||r.analysis.accounts||[]).slice(0,10),days:group(alerts,r=>[r.receivedAt.slice(0,10)]).sort((a,b)=>a.label.localeCompare(b.label)),excluded:unique.length-alerts.length};
}
