import {createHash} from 'node:crypto';

export const POLICY_VERSION='usuarios-sin-servidores-v1';
const folded=value=>String(value??'').normalize('NFKC').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
function contentText(value){
 let text=String(value??'');
 for(let i=0;i<3;i++)text=text.replace(/&#(x[0-9a-f]+|[0-9]+);?/gi,(_,n)=>{const point=n[0].toLowerCase()==='x'?parseInt(n.slice(1),16):Number(n);return point>0&&point<=0x10ffff?String.fromCodePoint(point):' ';}).replace(/&(amp|lt|gt|nbsp|colon|commat|tab|newline);/gi,(_,n)=>({amp:'&',lt:'<',gt:'>',nbsp:' ',colon:':',commat:'@',tab:' ',newline:' '}[n.toLowerCase()]));
 return folded(text).replace(/<[^>]*>/g,' ').replace(/\s+/g,' ');
}
const fail=(code)=>({eligible:false,code,policy:POLICY_VERSION});
const age=(value,now)=>{const n=Date.parse(value);return Number.isFinite(n)?now-n:Infinity;};
export function runtimeSettings(env={}){
 const number=(key,fallback,max)=>{const n=Number(env[key]??fallback);if(!Number.isInteger(n)||n<1||n>max)throw new Error(`Configuración no válida: ${key}`);return n;};
 const startAt=Date.parse(env.AUTOMATION_START_AT||'');
 return {enabled:env.BLOQUEO_AUTO_ACTIVO==='1',startAt,
  maxAgeMinutes:number('AUTOMATION_MAX_AGE_MINUTES',15,60),
  maxPerRun:number('AUTOMATION_MAX_PER_RUN',3,5),maxPerHour:number('AUTOMATION_MAX_PER_HOUR',10,20),
  userDomain:String(env.AUTOMATION_USER_DOMAIN||'sampol.com').toLowerCase(),
  trustedSenders:String(env.AUTOMATION_SOC_SENDERS||'soc-hackaton@sampol.com').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean)};
}

// The email is evidence, never policy/configuration. These controls only narrow SQL rules.
export function assessUserAlert(action,alert,evidence,rule,settings,now=Date.now()){
 if(action.accion!=='BLOQUEAR'||action.origen!=='AUTOMATICO')return fail('SOLO_BLOQUEO_AUTOMATICO');
 if(action.ip||action.ip_objetivo||!action.usuario_objetivo)return fail('IP_O_SERVIDOR_PROTEGIDO');
 const user=String(action.usuario_objetivo).trim().toLowerCase();
 if(!/^[a-z][a-z0-9._-]{1,63}@[a-z0-9.-]+$/.test(user)||user.split('@')[1]!==settings.userDomain)return fail('USUARIO_NO_IDENTIFICADO');
 if(/admin|root|system|service|servicio|svc|robot|bot|backup|sql|sync|monitor|breakglass|emergency|noreply|no-reply|support|soporte/i.test(user.split('@')[0]))return fail('CUENTA_PROTEGIDA');
 if(!alert||String(alert.usuario_implicado||'').trim().toLowerCase()!==user)return fail('OBJETIVO_NO_COINCIDE');
 if(!rule||rule.activa!==true||rule.regla_id!==action.regla||!['USUARIO','AMBOS'].includes(rule.objetivo)
  ||!Array.isArray(rule.prioridades)||!rule.prioridades.includes(alert.soc_prioridad)
  ||!Array.isArray(rule.peligrosidades)||!rule.peligrosidades.includes(alert.soc_peligrosidad)
  ||(rule.clases_incibe&&!rule.clases_incibe.includes(alert.incibe_clase_id)))return fail('REGLA_NO_VIGENTE');
 if(alert.es_sospechosa!==false||alert.remitente_confianza!==true||!Array.isArray(alert.inconsistencias)||alert.inconsistencias.length)return fail('ALERTA_NO_FIABLE');
 if(!['NUEVA','EN_REVISION','CONFIRMADA'].includes(alert.estado)||alert.soc_peligrosidad!=='CRITICO')return fail('ALERTA_NO_CRITICA_ACTIVA');
 if(!['INTRUSION','CONTENIDO_DANINO','COMPROMISO_INFORMACION'].includes(alert.incibe_clase_id))return fail('CLASE_NO_CONTENIBLE');
 const asset=folded(alert.equipo_afectado).trim();
 if(!/^(pc|laptop|portatil|workstation)-[a-z0-9-]+$/.test(asset))return fail('ACTIVO_NO_CONFIRMADO_COMO_PUESTO');
 if(!evidence||!evidence.eml_raw||evidence.correo_id!==alert.correo_id)return fail('FALTA_ORIGINAL');
 if(evidence.autenticacion_verificada!==true||!evidence.autenticacion_metodo||!evidence.autenticacion_emisor)return fail('REMITENTE_SIN_AUTENTICACION_VERIFICADA');
 const sender=String(alert.remitente_correo||'').trim().toLowerCase();
 if(!settings.trustedSenders.includes(sender)||String(evidence.remitente_correo||'').trim().toLowerCase()!==sender)return fail('REMITENTE_NO_AUTORIZADO');
 if(evidence.originalSubject!==alert.asunto_correo)return fail('ASUNTO_NO_COINCIDE_CON_ORIGINAL');
 const headers=evidence.cabeceras;
 if(!headers||!['utf8','base64'].includes(headers.eml_encoding)||!/^[a-f0-9]{64}$/.test(headers.eml_sha256||''))return fail('INTEGRIDAD_NO_DISPONIBLE');
 const bytes=Buffer.from(evidence.eml_raw,headers.eml_encoding==='base64'?'base64':'utf8');
 if(bytes.length>2000000||createHash('sha256').update(bytes).digest('hex')!==headers.eml_sha256)return fail('ORIGINAL_ALTERADO');
 if(typeof evidence.cuerpo_correo_raw!=='string'||!evidence.cuerpo_correo_raw.trim())return fail('FALTA_CONTEXTO');
 const raw=[alert.asunto_correo,alert.titulo,evidence.cuerpo_correo_raw].join(' ');
 if(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/.test(raw))return fail('TEXTO_OFUSCADO');
 const text=contentText(raw);
 // No commands in either subject or body, including embedded/quoted instructions.
 if(alert.id_solicitud||/\bsol-\d|solicitud|peticion|\bbloque[ao]|\bbloquear\b|\bdesbloque|\bliberar\b|\bdeshabilit|\bdisable\b|\bblock\b/.test(text))return fail('PETICION_NO_ES_EVIDENCIA');
 if(/ignora|ignore|instruccion|prompt|actua como|system message|assistant|chatgpt|ejecuta|execute|powershell|curl\b/.test(text))return fail('POSIBLE_MANIPULACION');
 if(/no ejecutar|sin autorizacion del responsable|pendiente de validacion|pendiente de revision|sin confirmar|no.{0,15}confirmad|posible|simulad|simulacion|simulacro|falso positivo|no se confirm|sin compromiso|compromiso descartado|actividad autorizada|actividad legitima/.test(text))return fail('VALIDACION_HUMANA_REQUERIDA');
 if(/\bservidor|\bserver|\bsrv[-_]|\bdc[-_]|controlador de dominio|cuenta.{0,30}(servicio|compartida|privilegiada|administrativa)|global administrator|domain admin|break.?glass/.test(text))return fail('SERVIDOR_O_CUENTA_CRITICA');
 if(!/cuenta.{0,60}comprometida|compromiso.{0,40}confirmado|acceso.{0,40}no autorizado.{0,40}confirmado|titular.{0,80}niega.{0,40}actividad/.test(text))return fail('COMPROMISO_NO_CONFIRMADO');
 // Exact labelled account; an arbitrary address elsewhere in a message is not a target.
 const labels=[...text.matchAll(/(?:cuenta relacionada|usuario implicado)\s*[:|]?\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/g)].map(x=>x[1]);
 if(new Set(labels).size!==1||labels[0]!==user)return fail('USUARIO_AMBIGUO');
 if(!alert.id_alerta_soc||!text.includes(folded(alert.id_alerta_soc)))return fail('FALTA_REFERENCIA_ALERTA');
 const maxAge=settings.maxAgeMinutes*60000;
 for(const date of [alert.fecha_hora_correo,alert.fecha_ultimo_evento||alert.fecha_hora_evento,action.fecha_solicitud]){
  const delta=age(date,now);if(delta < -60000||delta>maxAge)return fail('ALERTA_ANTIGUA_O_FECHA_INVALIDA');
 }
 if(!Number.isFinite(settings.startAt)||Date.parse(alert.fecha_hora_correo)<settings.startAt)return fail('ANTERIOR_A_ACTIVACION');
 return {eligible:true,code:'COMPROMISO_USUARIO_VERIFICADO',policy:POLICY_VERSION,user,evidenceHash:headers.eml_sha256};
}

export function targetMatches(record,user){return record?.equipo_id===2&&record?.tipo==='usuario'&&record?.valor===user&&record?.activo===true&&Number.isSafeInteger(record?.id);}
