import { API_BASE, analyze, normalizeText, validIPv4, validAccount } from './soc.mjs';
import {runtimeEnv} from './runtime.mjs';
export {runtimeEnv};
export function db() {const value=runtimeEnv().DB;if(!value) throw new Error('Base de datos no disponible.');return value as D1Database;}
export function json(value:unknown,status=200){return Response.json(value,{status,headers:{'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});}
export class HttpError extends Error{constructor(public status:number,message:string){super(message);}}
export function failure(error:unknown){return json({error:error instanceof HttpError?error.message:'La operación no se completó. Revisa configuración y auditoría.'},error instanceof HttpError?error.status:500);}
export async function audit(actor:string,event:string,detail:unknown){await db().prepare('INSERT INTO audit (id,actor,event,detail,created_at) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(),actor,event,JSON.stringify(detail),new Date().toISOString()).run();}
export function config(){const e=runtimeEnv();return {ingestMode:e.INGEST_MODE||'power-automate',outlookReady:e.INGEST_MODE==='power-automate'&&!!e.OUTLOOK_MAILBOX&&!!e.SOC_SENDERS,blockingReady:!!e.BLOCK_API_KEY,approversReady:!!e.APPROVER_EMAILS,storageReady:!!e.DB&&!!e.BUCKET,mailbox:e.OUTLOOK_MAILBOX||null,senders:e.SOC_SENDERS||null,team:2};}
async function timedFetch(url:string,init:RequestInit={}){return fetch(url,{...init,signal:AbortSignal.timeout(15000)});}
export async function apiFetch(path:string,method='GET',payload?:unknown){const e=runtimeEnv();if(!e.BLOCK_API_KEY)throw new HttpError(409,'Falta configurar la clave del equipo 2.');return timedFetch(`${API_BASE}/equipo-2/${path}`,{method,headers:{'X-API-Key':e.BLOCK_API_KEY,'Content-Type':'application/json'},...(payload?{body:JSON.stringify(payload)}:{})});}
async function findTarget(type:string,value:string){
 for(let offset=0;offset<1000;offset+=100){
  const r=await apiFetch(`bloqueos?tipo=${type}&limit=100&offset=${offset}`);if(!r.ok)throw new HttpError(502,'La consulta de comprobación no está disponible.');
  const rows=await r.json() as any;if(!Array.isArray(rows))throw new HttpError(502,'Respuesta de comprobación no válida.');
  const found=rows.find((row:any)=>row.equipo_id===2&&row.tipo===type&&row.valor===value);if(found)return found;if(rows.length<100)return null;
 }
 throw new HttpError(409,'Comprobación limitada a 1000 registros. Requiere reconciliación externa.');
}
export async function reconcile(actor:string,id:string){
 const allowed=String(runtimeEnv().APPROVER_EMAILS||'').toLowerCase().split(',').map(s=>s.trim());
 if(!allowed.includes(actor.toLowerCase()))throw new HttpError(403,'Se requiere responsable autorizado.');
 const op=await db().prepare('SELECT * FROM operations WHERE id=?').bind(id).first() as any;
 if(!op)throw new HttpError(404,'Operación no encontrada.');
 if(!['Resultado desconocido','En curso','Preparado','Rechazado por API'].includes(op.state))throw new HttpError(409,'Esta operación no requiere reconciliación.');
 // Read-only external check: never replay POST, never claim causality from current state.
 const found=await findTarget(op.type,op.value);
 const matches=found&&found.activo===(op.action==='bloquear');
 if(!matches){await audit(actor,'reconciliacion_pendiente',{operation:id});return {state:op.state,summary:'El estado esperado no se ha confirmado. Se mantiene el bloqueo de reintentos; revisar manualmente.'};}
 const message='Estado actual confirmado por consulta posterior; no acredita por sí solo qué solicitud lo originó.';
 await db().batch([
  db().prepare("UPDATE operations SET state='Verificado',response=? WHERE id=?").bind(message,id),
  db().prepare('DELETE FROM target_locks WHERE key=? AND operation_id=?').bind(`${op.type}|${op.value.toLowerCase()}`,id),
 ]);
 await audit(actor,'estado_reconciliado',{operation:id,blockId:found.id});
 return {state:'Verificado',summary:message};
}
export async function performAction(actor:string,input:any){
 const approvers=String(runtimeEnv().APPROVER_EMAILS||'').toLowerCase().split(',').map(s=>s.trim());
 if(!approvers.includes(actor.toLowerCase()))throw new HttpError(403,'La cuenta actual no está configurada como responsable autorizado.');
 const {incidentId,type,value,action,reason,validated}=input;
 if(!['ip','usuario'].includes(type)||!['bloquear','liberar'].includes(action)||typeof reason!=='string'||reason.trim().length<12||reason.length>2000||validated!==true)throw new HttpError(400,'Confirma la validación y añade una justificación de al menos 12 caracteres.');
 if(!(type==='ip'?validIPv4(value):validAccount(value)))throw new HttpError(400,'Objetivo no válido. La extracción automática admite IPv4 y cuentas de correo.');
 const incident=await db().prepare('SELECT * FROM incidents WHERE id=?').bind(incidentId).first() as any;
 if(!incident)throw new HttpError(404,'Incidente no encontrado.');const analysis=JSON.parse(incident.analysis);
 if(!analysis.classificationReviewed||['No es alerta','Falsa alarma','Cerrada'].includes(incident.status))throw new HttpError(409,'Revisa y confirma la clasificación del incidente antes de contener.');
 if(!(type==='ip'?analysis.ips:analysis.accounts).includes(value))throw new HttpError(400,'El objetivo no pertenece a los candidatos del incidente.');
 if(!runtimeEnv().BUCKET||!await runtimeEnv().BUCKET.head(incident.evidence_key))throw new HttpError(409,'No está disponible la evidencia original. Revisión requerida antes de actuar.');
 if(!runtimeEnv().BLOCK_API_KEY)throw new HttpError(409,'Configura primero la clave del equipo 2.');
 if(action==='liberar'&&!await db().prepare("SELECT id FROM operations WHERE incident_id=? AND type=? AND value=? AND action='bloquear' AND state='Verificado'").bind(incidentId,type,value).first())throw new HttpError(409,'La liberación requiere un bloqueo verificado de este expediente.');
 const id=crypto.randomUUID();const now=new Date().toISOString();
 const insert=await db().prepare('INSERT OR IGNORE INTO operations (id,incident_id,action,type,value,actor,reason,state,created_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(id,incidentId,action,type,value,actor,reason.trim(),'Preparado',now).run();
 if(!insert.meta.changes)throw new HttpError(409,'Ya existe esta operación. Revisa el registro antes de repetirla.');
 const lockKey=`${type}|${value.toLowerCase()}`;const lock=await db().prepare('INSERT OR IGNORE INTO target_locks (key,operation_id,created_at) VALUES (?,?,?)').bind(lockKey,id,now).run();
 if(!lock.meta.changes){await db().prepare("UPDATE operations SET state='No ejecutado',response=? WHERE id=?").bind('Otro proceso tiene este objetivo bloqueado para revisión.',id).run();throw new HttpError(409,'Objetivo ocupado por otra operación. Requiere reconciliación.');}
 await audit(actor,'contencion_autorizada',{operation:id,incidentId,type,value,action,reason});
 // Intention is durably stored before the request. Unknown outcomes retain the target lock.
 let state='Resultado desconocido';let httpStatus:number|null=null;let summary='Reconciliar con la API antes de repetir.';
 try{
  await db().prepare("UPDATE operations SET state='En curso' WHERE id=?").bind(id).run();
  const response=await apiFetch(action,'POST',{[type]:value});httpStatus=response.status;
  const result=await response.json().catch(()=>null) as any;
  if(!response.ok){state=response.status>=500||response.status===429?'Resultado desconocido':'Rechazado por API';summary=`HTTP ${response.status}. Revisión manual requerida.`;}
  else if(result?.bloqueo?.equipo_id===2 && result.bloqueo.tipo===type && result.bloqueo.valor===value && result.bloqueo.activo===(action==='bloquear')){
   const match=await findTarget(type,value);
   if(match?.id===result.bloqueo.id&&match?.activo===(action==='bloquear')){state='Verificado';summary=`Operación registrada y verificada en API. Bloqueo #${result.bloqueo.id}.`;}
   else summary='Respuesta recibida; la consulta independiente no confirma el estado esperado. Reconciliar.';
  }else summary='Respuesta inesperada. Reconciliar sin repetir el POST.';
 }catch{summary='No se pudo confirmar el resultado. No se ha reintentado el POST.';}
 await db().prepare('UPDATE operations SET state=?,response=?,http_status=? WHERE id=?').bind(state,summary,httpStatus,id).run();
 await audit(actor,'resultado_contencion',{operation:id,state,httpStatus});
 if(state==='Verificado')await db().prepare('DELETE FROM target_locks WHERE key=? AND operation_id=?').bind(lockKey,id).run();
 return {id,state,summary,httpStatus};
}
