import {structuredAnalysis} from './taxonomy.mjs';
export const API_BASE = 'https://hackathon-api-a6ckg4g2ejg4cda4.francecentral-01.azurewebsites.net';
export function validIPv4(value) {
 return typeof value === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(x => Number(x) <= 255 && String(Number(x)) === x);
}
export function validAccount(value) { return typeof value === 'string' && /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value) && value.length <= 255; }
export function analyze(subject, body) {
 const plainBody = body.replace(/\*\*/g,'').replace(/\|/g,' ').replace(/\s+/g,' ');
 const all = `${subject}\n${plainBody}`; const normalized = all.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 const reference = all.match(/\bSOC-\d{8}-\d{3}-[A-Z0-9]+\b/i)?.[0] || null;
 const originalPriority = subject.match(/\bP[0-9]+\b/i)?.[0] || 'Sin etiqueta';
 const subjectLevel=subject.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 const explicit=subjectLevel.match(/\[(critico|critica|alto|alta|medio|media|bajo|baja)\]/)?.[1];
 const priority = explicit?({critico:'Crítica',critica:'Crítica',alto:'Alta',alta:'Alta',medio:'Media',media:'Media',bajo:'Baja',baja:'Baja'}[explicit]):/\bcritic[oa]\b|ransomware|global administrator/.test(normalized) ? 'Crítica' : /\balta\b|privilegiad|administrativ|exfiltracion/.test(normalized) ? 'Alta' : /\bmedia\b|fuerza bruta|phishing/.test(normalized) ? 'Media' : /\bbaja\b/.test(normalized) ? 'Baja' : 'Sin clasificar';
 const topics = [];
 if (/cuenta|sesion|credencial|acceso|administrador|administrativ/.test(normalized)) topics.push('Identidad y accesos');
 if (/phishing|suplantacion|correo malicioso/.test(normalized)) topics.push('Phishing');
 if (/malware|ransomware|troyano/.test(normalized)) topics.push('Malware');
 if (/exfiltr|fuga|datos expuestos/.test(normalized)) topics.push('Datos y exfiltración');
 if (/ddos|denegacion|cortafuegos|puerto|trafico/.test(normalized)) topics.push('Red y disponibilidad');
 if (/vulnerabilidad|cve-|parche/.test(normalized)) topics.push('Vulnerabilidades');
 if (!topics.length) topics.push('Otros');
 const accounts = [...new Set([...plainBody.matchAll(/(?:cuenta\s+privilegiada|cuenta\s+relacionada)\s*[:|]?\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/gi)].map(m => m[1].toLowerCase()))].filter(validAccount);
 // Only source addresses stated explicitly in the narrative. Other IPs are evidence, not targets.
 const ips = [...new Set([...plainBody.matchAll(/(?:desde|IP\s+de\s+origen\s*:)\s*((?:\d{1,3}\.){3}\d{1,3})\b/gi)].map(m=>m[1]))].filter(validIPv4);
 const warnings = [];
 if (!reference) warnings.push('No se ha identificado una referencia SOC.');
 if (/direccion relacionada\s*[:|]?\s*\d{5,}/.test(normalized)) warnings.push('La dirección de la tabla no tiene un formato IP válido. No se ha corregido.');
 if (/\bcritic[oa]\b/.test(normalized) && /criticidad\s*[:|]?\s*media/.test(normalized)) warnings.push('El aviso contiene etiquetas de criticidad diferentes; confirmar prioridad.');
 if (/no ejecutar|sin autorizacion|pendiente de validacion/.test(normalized)) warnings.push('El aviso exige validación o autorización antes de contener.');
 if (accounts.length > 1 || ips.length > 1) warnings.push('Hay varios objetivos candidatos. Revisar el alcance individualmente.');
 if (!accounts.length && !ips.length) warnings.push('No hay objetivos válidos extraídos; requiere revisión manual.');
 return {...structuredAnalysis(subject,body),reference, originalPriority, priority, topics, accounts, ips, warnings, approvalRequired:true,
  classificationReason: priority === 'Sin clasificar' ? 'Sin indicadores de prioridad reconocidos. Revisión necesaria.' : `Reglas textuales: prioridad ${priority.toLowerCase()}. La etiqueta ${originalPriority} se conserva sin equivalencias numéricas.`,
  ruleVersion:'soc-rules-2.0-incibe'};
}
export function normalizeText(value) { return String(value || '').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]*>/g,' ').replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/\s+/g,' ').trim(); }
export const demoMessages = [
 {id:'demo-1',subject:'[SOC][P4][CRÍTICO] Uso de cuenta administrativa desde origen no autorizado',sender:'soc@example.invalid',receivedAt:'2026-11-03T09:42:00Z',body:'SOC-20261103-002-DEMO01. La cuenta privilegiada admin.demo@example.invalid completó una sesión desde 198.51.100.107 y añadió una identidad al grupo de administradores sin cambio autorizado. Cuenta relacionada admin.demo@example.invalid. Dirección relacionada 19851100107. Criticidad Media. No ejecutar una contención sin autorización del responsable.',status:'Pendiente'},
 {id:'demo-2',subject:'[SOC][ALTA] Posible exfiltración desde equipo de laboratorio',sender:'soc@example.invalid',receivedAt:'2026-11-03T09:28:00Z',body:'SOC-20261103-003-DEMO02. Posible fuga de datos y tráfico anómalo. IP de origen: 203.0.113.42. Revisar evidencia y alcance antes de contener.',status:'Pendiente'},
 {id:'demo-3',subject:'[SOC][MEDIA] Campaña de phishing detectada',sender:'soc@example.invalid',receivedAt:'2026-11-03T08:51:00Z',body:'SOC-20261103-004-DEMO03. Correo de suplantación recibido por varias personas. Sin indicadores de compromiso confirmados. Revisar enlaces y evidencias.',status:'Pendiente'},
 {id:'demo-4',subject:'[SOC][ALTA] Detección de malware en endpoint',sender:'soc@example.invalid',receivedAt:'2026-11-03T08:30:00Z',body:'SOC-20261103-005-DEMO04. Malware bloqueado por EDR. Revisión de persistencia pendiente.',status:'Pendiente'},
 {id:'demo-5',subject:'[SOC][BAJA] Vulnerabilidad pendiente de parche',sender:'soc@example.invalid',receivedAt:'2026-11-03T07:40:00Z',body:'SOC-20261103-006-DEMO05. Vulnerabilidad en servidor de pruebas sin explotación observada. Aplicar parche en ventana de mantenimiento.',status:'Pendiente'},
 {id:'demo-6',subject:'[SOC][MEDIA] Intentos de acceso repetidos',sender:'soc@example.invalid',receivedAt:'2026-11-03T07:12:00Z',body:'SOC-20261103-007-DEMO06. Fuerza bruta desde 192.0.2.61. No se ha confirmado inicio de sesión correcto.',status:'Pendiente'}
].map(m=>({...m,analysis:analyze(m.subject,m.body),demo:true}));
