import {randomUUID} from 'node:crypto';
import PostalMime from 'postal-mime';
import {assessUserAlert,POLICY_VERSION} from './automation-policy.mjs';

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
 const store={
  async readiness(){
   const rows=(await query("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('acciones_bloqueo','lista_blanca','reglas_bloqueo_auto','v_alertas','v_evidencias_automatizacion','decisiones_bloqueo_auto','v_fases_alertas')")).rows;
   const required={acciones_bloqueo:['accion_id','estado','origen','respuesta_api','simulacion'],lista_blanca:['tipo','usuario','activo'],reglas_bloqueo_auto:['regla_id','activa','exigir_criticidad_cuerpo','inconsistencias_ignoradas','antiguedad_max_minutos'],v_alertas:['correo_id','remitente_confianza','inconsistencias','criticidad_cuerpo'],v_evidencias_automatizacion:['correo_id','remitente_correo','cuerpo_correo_raw','eml_raw','cabeceras','autenticacion_verificada','autenticacion_metodo','autenticacion_emisor','integridad_ok']};
   if(settings.policy==='sql'){required.decisiones_bloqueo_auto=['accion_id','alerta_id','regla_id','tipo_objetivo','valor_objetivo','decision'];required.reglas_bloqueo_auto.push('criticidades_cuerpo','criticidades_corroboradas','min_alertas_corroboracion','ventana_corroboracion_min','fase_disparadora','fases_previas','min_fases_previas');required.v_fases_alertas=['alerta_id','fase'];}
   const missing=[];for(const [table,columns] of Object.entries(required))for(const column of columns)if(!rows.some(r=>r.table_name===table&&r.column_name===column))missing.push(`${table}.${column}`);
   return {ready:missing.length===0,missing};
  },
  async lock(){return (await query('SELECT pg_try_advisory_lock(724103,2) AS locked')).rows[0].locked;},
  async unlock(){await query('SELECT pg_advisory_unlock(724103,2)');},
  async pending(limit){return (await query("SELECT *,host(ip_objetivo) AS ip FROM public.acciones_bloqueo WHERE estado='PENDIENTE' AND (origen='AUTOMATICO' OR ($2::boolean AND origen='MANUAL' AND regla='MANUAL:D-007')) AND NOT simulacion ORDER BY fecha_solicitud,accion_id LIMIT $1",[limit,settings.policy==='sql'])).rows;},
  async context(action){
   const alert=(await query('SELECT * FROM public.v_alertas WHERE alerta_id=$1',[action.alerta_id])).rows[0];
   if(settings.policy==='sql'&&action.origen==='MANUAL'&&action.regla==='MANUAL:D-007'){
    const row=(await query("SELECT * FROM public.acciones_bloqueo WHERE accion_id=$1 AND alerta_id=$2 AND usuario_objetivo=$3 AND origen='MANUAL' AND regla='MANUAL:D-007' AND accion='BLOQUEAR' AND ip_objetivo IS NULL AND NOT simulacion AND estado='PENDIENTE'",[action.accion_id,action.alerta_id,action.usuario_objetivo])).rows[0];
    const approved=!!row&&typeof row.solicitado_por==='string'&&!!row.solicitado_por.trim()&&!/^AUTO:/i.test(row.solicitado_por)&&typeof row.motivo==='string'&&!!row.motivo.trim();
    return {alert,evidence:alert?await evidenceFor(alert.correo_id):null,rule:{regla_id:action.regla,manualDecisionApproved:approved,min_alertas:1,ventana_minutos:120,antiguedad_max_minutos:null}};
   }
   const rule=(await query('SELECT '+(settings.policy==='sql'?'fase_disparadora,fases_previas,min_fases_previas,criticidades_cuerpo,criticidades_corroboradas,min_alertas_corroboracion,ventana_corroboracion_min,':'')+'regla_id,activa,objetivo,prioridades::text[] AS prioridades,peligrosidades::text[] AS peligrosidades,clases_incibe,min_alertas,ventana_minutos,exigir_criticidad_cuerpo,inconsistencias_ignoradas,antiguedad_max_minutos FROM public.reglas_bloqueo_auto WHERE regla_id=$1',[action.regla])).rows[0];
   if(settings.policy==='sql'&&rule&&alert){
    rule.sqlDecisionApproved=(await query("SELECT 1 FROM public.decisiones_bloqueo_auto WHERE accion_id=$1 AND alerta_id=$2 AND regla_id=$3 AND tipo_objetivo='USUARIO' AND valor_objetivo=$4 AND decision='BLOQUEAR'",[action.accion_id,action.alerta_id,action.regla,action.usuario_objetivo])).rowCount===1;
    if(action.regla==='AUTO-06'){
     rule.phaseMatches=rule.fase_disparadora==='COMPROMISO'&&(await query('SELECT 1 FROM public.v_fases_alertas WHERE alerta_id=$1 AND fase=$2',[alert.alerta_id,rule.fase_disparadora])).rowCount===1;
     rule.min_alertas=rule.min_fases_previas;
    }
    const body=String(alert.criticidad_cuerpo||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
    if(action.regla!=='AUTO-06'&&/^(medi|baj)/.test(body)){rule.min_alertas=Math.max(rule.min_alertas,rule.min_alertas_corroboracion);rule.ventana_minutos=rule.ventana_corroboracion_min;}
   }
   return {alert,rule,evidence:alert?await evidenceFor(alert.correo_id):null};
  },
  async corroborations(action,context){
   if(settings.policy==='sql'&&action.origen==='MANUAL')return context.rule.manualDecisionApproved?1:0;
   if(settings.policy==='sql'&&action.regla==='AUTO-06'){
    const r=context.rule;
    if(!Number.isInteger(r.min_fases_previas)||r.min_fases_previas<1||!Number.isInteger(r.ventana_minutos)||r.ventana_minutos<1||!Array.isArray(r.fases_previas)||r.fases_previas.some(f=>!['ACCESO_INICIAL','CREDENCIALES'].includes(f)))return 0;
    const rows=(await query("SELECT a.*,f.fase FROM public.v_alertas a JOIN public.v_fases_alertas f ON f.alerta_id=a.alerta_id WHERE lower(a.usuario_implicado)=lower($1) AND f.fase=ANY($2::text[]) AND a.alerta_id<>$3 AND coalesce(a.fecha_hora_evento,a.fecha_hora_correo) BETWEEN coalesce($4::timestamptz,$5::timestamptz)-make_interval(mins=>$6::int) AND coalesce($4::timestamptz,$5::timestamptz) ORDER BY a.fecha_hora_correo LIMIT 100",[action.usuario_objetivo,r.fases_previas,action.alerta_id,context.alert.fecha_hora_evento,context.alert.fecha_hora_correo,r.ventana_minutos])).rows;
    const phases=new Set(),ids=new Set([context.alert.id_alerta_soc]);
    for(const alert of rows){if(!alert.id_alerta_soc||ids.has(alert.id_alerta_soc))continue;const evidence=await evidenceFor(alert.correo_id);
     if(assessUserAlert({...action,alerta_id:alert.alerta_id},alert,evidence,{...r,phaseMatches:true},settings).eligible){ids.add(alert.id_alerta_soc);phases.add(alert.fase);}}
    return phases.size;
   }
   const end=context.alert.fecha_ultimo_evento||context.alert.fecha_hora_evento;
   const rows=(await query("SELECT * FROM public.v_alertas WHERE lower(usuario_implicado)=lower($1) AND coalesce(fecha_ultimo_evento,fecha_hora_evento) BETWEEN $2::timestamptz - make_interval(mins=>$3::int) AND $2::timestamptz ORDER BY fecha_hora_correo DESC LIMIT 100",[action.usuario_objetivo,end,context.rule.ventana_minutos])).rows;
   let count=0;const ids=new Set();for(const alert of rows){const evidence=await evidenceFor(alert.correo_id);if(!ids.has(alert.id_alerta_soc)&&assessUserAlert(settings.policy==='sql'?{...action,alerta_id:alert.alerta_id}:action,alert,evidence,context.rule,settings).eligible){ids.add(alert.id_alerta_soc);count++;}}
   return count;
  },
  async protectedUser(user){return (await query("SELECT 1 FROM public.lista_blanca WHERE activo AND tipo='USUARIO' AND lower(usuario)=lower($1) LIMIT 1",[user])).rowCount>0;},
  async unresolved(user,id){return (await query("SELECT 1 FROM public.acciones_bloqueo WHERE lower(usuario_objetivo)=lower($1) AND accion_id<>$2 AND estado IN ('ERROR','EN_CURSO','DESCONOCIDO') AND NOT simulacion LIMIT 1",[user,id])).rowCount>0;},
  async releasedSince(user,since){return (await query("SELECT 1 FROM public.acciones_bloqueo WHERE lower(usuario_objetivo)=lower($1) AND accion='LIBERAR' AND NOT simulacion AND estado IN ('PENDIENTE','EN_CURSO','EJECUTADA','ERROR','DESCONOCIDO') AND fecha_solicitud >= $2 LIMIT 1",[user,since])).rowCount>0;},
  async hourlyAttempts(){return Number((await query("SELECT count(*) FROM public.acciones_bloqueo WHERE NOT simulacion AND respuesta_api->'automation'->>'claimedAt' >= $1",[new Date(Date.now()-3600000).toISOString()])).rows[0].count);},
  async omit(action,code){
   await query("UPDATE public.acciones_bloqueo SET estado='OMITIDA',exito=false,fecha_respuesta=now(),respuesta_api=$1::jsonb WHERE accion_id=$2 AND estado='PENDIENTE'",[JSON.stringify({automation:{phase:'review_required',code,policy:POLICY_VERSION}}),action.accion_id]);
  },
  async claim(action,meta){
   const token=randomUUID();
   await query('BEGIN');
   try{
    await query("SELECT pg_advisory_xact_lock(hashtext('bloqueo:USUARIO:' || lower($1)))",[action.usuario_objetivo]);
    await query('LOCK TABLE public.lista_blanca,public.reglas_bloqueo_auto IN SHARE MODE');
    if(settings.policy==='sql')await query('LOCK TABLE public.alertas,public.bandeja_entrada,public.decisiones_bloqueo_auto,public.config_autenticacion IN SHARE MODE');
    const current=(await query('SELECT * FROM public.acciones_bloqueo WHERE accion_id=$1 FOR UPDATE',[action.accion_id])).rows[0];
    if(!current||['origen','regla','alerta_id','usuario_objetivo','accion','solicitado_por','motivo'].some(k=>current[k]!==action[k])){await query('ROLLBACK');return null;}
    const latest=await store.context(action);
    const checked=assessUserAlert(action,latest.alert,latest.evidence,latest.rule,settings);
    if(!checked.eligible||checked.evidenceHash!==meta.evidenceHash||await store.protectedUser(action.usuario_objetivo)||await store.unresolved(action.usuario_objetivo,action.accion_id)||await store.releasedSince(action.usuario_objetivo,latest.alert.fecha_hora_evento||latest.alert.fecha_hora_correo)||await store.corroborations(action,latest)<latest.rule.min_alertas){await query('ROLLBACK');return null;}
    const result=await query("UPDATE public.acciones_bloqueo SET estado='ERROR',exito=false,respuesta_api=$1::jsonb WHERE accion_id=$2 AND estado='PENDIENTE' AND origen=$6 AND (origen='AUTOMATICO' OR ($7::boolean AND origen='MANUAL' AND regla='MANUAL:D-007')) AND accion='BLOQUEAR' AND ip_objetivo IS NULL AND NOT simulacion AND usuario_objetivo=$3 AND regla=$4 AND alerta_id=$5 RETURNING accion_id",[JSON.stringify({automation:{...meta,token,phase:'outcome_unknown',claimedAt:new Date().toISOString()}}),action.accion_id,action.usuario_objetivo,action.regla,action.alerta_id,action.origen,settings.policy==='sql']);
    await query('COMMIT');return result.rowCount?token:null;
   }catch(error){await query('ROLLBACK').catch(()=>{});throw error;}
  },
  async finish(action,token,result){
   const done=result.phase==='verified';
   const updated=await query("UPDATE public.acciones_bloqueo SET estado=$1,exito=$2,http_status=$3,fecha_respuesta=now(),respuesta_api=jsonb_set(respuesta_api,'{automation}',(respuesta_api->'automation') || $4::jsonb) WHERE accion_id=$5 AND estado='ERROR' AND respuesta_api->'automation'->>'token'=$6",[done?'EJECUTADA':'ERROR',done,result.httpStatus,JSON.stringify(result),action.accion_id,token]);
   if(updated.rowCount!==1)throw new Error('La operación cambió; comprobar sin repetir POST');
  }
 };return store;
}
