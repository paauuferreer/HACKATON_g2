import {randomUUID} from 'node:crypto';
import PostalMime from 'postal-mime';
import {assessUserAlert} from './automation-policy.mjs';

export function postgresStore(client,settings){
 const query=(sql,args=[])=>client.query(sql,args);
 async function evidenceFor(id){
  const evidence=(await query('SELECT * FROM public.v_evidencias_automatizacion WHERE correo_id=$1',[id])).rows[0];
  if(!evidence?.eml_raw)return null;
  if(!['base64','utf8'].includes(evidence.cabeceras?.eml_encoding))return null;
  const bytes=Buffer.from(evidence.eml_raw,evidence.cabeceras.eml_encoding==='base64'?'base64':'utf8');
  if(bytes.length>2000000)return null;
  try{
   const mime=await PostalMime.parse(bytes,{maxNestingDepth:20,maxHeadersSize:100000});
   if(String(mime.from?.address||'').toLowerCase()!==String(evidence.remitente_correo||'').toLowerCase())return null;
   if(mime.attachments?.length)return null;
   return {...evidence,cuerpo_correo_raw:mime.text||mime.html||'',originalSubject:mime.subject};
  }catch{return null;}
 }
 return {
  async readiness(){
   const rows=(await query("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('acciones_bloqueo','lista_blanca','reglas_bloqueo_auto','v_alertas','v_evidencias_automatizacion')")).rows;
   const required={acciones_bloqueo:['accion_id','estado','origen','respuesta_api','simulacion'],lista_blanca:['tipo','usuario','activo'],reglas_bloqueo_auto:['regla_id','activa'],v_alertas:['correo_id','remitente_confianza','inconsistencias'],v_evidencias_automatizacion:['correo_id','remitente_correo','cuerpo_correo_raw','eml_raw','cabeceras','autenticacion_verificada','autenticacion_metodo','autenticacion_emisor']};
   const missing=[];for(const [table,columns] of Object.entries(required))for(const column of columns)if(!rows.some(r=>r.table_name===table&&r.column_name===column))missing.push(`${table}.${column}`);
   return {ready:missing.length===0,missing};
  },
  async lock(){return (await query('SELECT pg_try_advisory_lock(724103,2) AS locked')).rows[0].locked;},
  async unlock(){await query('SELECT pg_advisory_unlock(724103,2)');},
  async pending(limit){return (await query("SELECT *,host(ip_objetivo) AS ip FROM public.acciones_bloqueo WHERE estado='PENDIENTE' AND origen='AUTOMATICO' AND NOT simulacion ORDER BY fecha_solicitud,accion_id LIMIT $1",[limit])).rows;},
  async context(action){
   const alert=(await query('SELECT * FROM public.v_alertas WHERE alerta_id=$1',[action.alerta_id])).rows[0];
   const rule=(await query('SELECT regla_id,activa,objetivo,prioridades::text[] AS prioridades,peligrosidades::text[] AS peligrosidades,clases_incibe,min_alertas,ventana_minutos FROM public.reglas_bloqueo_auto WHERE regla_id=$1',[action.regla])).rows[0];
   return {alert,rule,evidence:alert?await evidenceFor(alert.correo_id):null};
  },
  async corroborations(action,context){
   const end=context.alert.fecha_ultimo_evento||context.alert.fecha_hora_evento;
   const rows=(await query("SELECT * FROM public.v_alertas WHERE lower(usuario_implicado)=lower($1) AND coalesce(fecha_ultimo_evento,fecha_hora_evento) BETWEEN $2::timestamptz - make_interval(mins=>$3::int) AND $2::timestamptz ORDER BY fecha_hora_correo DESC LIMIT 100",[action.usuario_objetivo,end,context.rule.ventana_minutos])).rows;
   let count=0;for(const alert of rows){const evidence=await evidenceFor(alert.correo_id);if(assessUserAlert(action,alert,evidence,context.rule,settings).eligible)count++;}
   return count;
  },
  async protectedUser(user){return (await query("SELECT 1 FROM public.lista_blanca WHERE activo AND tipo='USUARIO' AND lower(usuario)=lower($1) LIMIT 1",[user])).rowCount>0;},
  async unresolved(user,id){return (await query("SELECT 1 FROM public.acciones_bloqueo WHERE lower(usuario_objetivo)=lower($1) AND accion_id<>$2 AND estado='ERROR' AND NOT simulacion LIMIT 1",[user,id])).rowCount>0;},
  async releasedSince(user,since){return (await query("SELECT 1 FROM public.acciones_bloqueo WHERE lower(usuario_objetivo)=lower($1) AND accion='LIBERAR' AND NOT simulacion AND estado IN ('PENDIENTE','EJECUTADA','ERROR') AND fecha_solicitud >= $2 LIMIT 1",[user,since])).rowCount>0;},
  async hourlyAttempts(){return Number((await query("SELECT count(*) FROM public.acciones_bloqueo WHERE NOT simulacion AND respuesta_api->'automation'->>'claimedAt' >= $1",[new Date(Date.now()-3600000).toISOString()])).rows[0].count);},
  async omit(action,code){
   await query("UPDATE public.acciones_bloqueo SET estado='OMITIDA',exito=false,fecha_respuesta=now(),respuesta_api=$1::jsonb WHERE accion_id=$2 AND estado='PENDIENTE'",[JSON.stringify({automation:{phase:'review_required',code,policy:'usuarios-sin-servidores-v1'}}),action.accion_id]);
  },
  async claim(action,meta){
   const token=randomUUID();
   await query('BEGIN');
   try{
    await query("SELECT pg_advisory_xact_lock(hashtext('bloqueo:USUARIO:' || lower($1)))",[action.usuario_objetivo]);
    const blocked=await query("SELECT 1 FROM public.acciones_bloqueo WHERE lower(usuario_objetivo)=lower($1) AND estado='ERROR' AND accion_id<>$2 AND NOT simulacion LIMIT 1",[action.usuario_objetivo,action.accion_id]);
    if(blocked.rowCount){await query('ROLLBACK');return null;}
    const result=await query("UPDATE public.acciones_bloqueo SET estado='ERROR',exito=false,respuesta_api=$1::jsonb WHERE accion_id=$2 AND estado='PENDIENTE' AND origen='AUTOMATICO' AND accion='BLOQUEAR' AND ip_objetivo IS NULL AND NOT simulacion AND usuario_objetivo=$3 AND regla=$4 AND alerta_id=$5 RETURNING accion_id",[JSON.stringify({automation:{...meta,token,phase:'outcome_unknown',claimedAt:new Date().toISOString()}}),action.accion_id,action.usuario_objetivo,action.regla,action.alerta_id]);
    await query('COMMIT');return result.rowCount?token:null;
   }catch(error){await query('ROLLBACK').catch(()=>{});throw error;}
  },
  async finish(action,token,result){
   const done=result.phase==='verified';
   const updated=await query("UPDATE public.acciones_bloqueo SET estado=$1,exito=$2,http_status=$3,fecha_respuesta=now(),respuesta_api=jsonb_set(respuesta_api,'{automation}',(respuesta_api->'automation') || $4::jsonb) WHERE accion_id=$5 AND estado='ERROR' AND respuesta_api->'automation'->>'token'=$6",[done?'EJECUTADA':'ERROR',done,result.httpStatus,JSON.stringify(result),action.accion_id,token]);
   if(updated.rowCount!==1)throw new Error('La operación cambió; comprobar sin repetir POST');
  }
 };
}
