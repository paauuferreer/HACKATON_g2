import {assessUserAlert,targetMatches,POLICY_VERSION} from './automation-policy.mjs';

// store.claim() MUST COMMIT before this function can send a POST.
// Any exception thereafter leaves ERROR/outcome_unknown, quarantining the target.
export async function processAction(action,{store,api,settings,now=()=>Date.now(),dryRun=true}){
 if(!dryRun&&!settings.enabled)return {outcome:'disabled'};
 const context=await store.context(action);
 const decision=assessUserAlert(action,context.alert,context.evidence,context.rule,settings,now());
 if(!decision.eligible){if(!dryRun)await store.omit(action,decision.code);return {outcome:'review',code:decision.code};}
 if(await store.protectedUser(decision.user)){if(!dryRun)await store.omit(action,'LISTA_BLANCA');return {outcome:'review',code:'LISTA_BLANCA'};}
 if(!Number.isInteger(context.rule.min_alertas)||context.rule.min_alertas<1||await store.corroborations(action,context)<context.rule.min_alertas){
  if(!dryRun)await store.omit(action,'CORROBORACION_INSUFICIENTE');return {outcome:'review',code:'CORROBORACION_INSUFICIENTE'};
 }
 if(await store.unresolved(decision.user,action.accion_id))return {outcome:'review',code:'RESULTADO_PREVIO_DESCONOCIDO'};
 if(await store.releasedSince(decision.user,context.alert.fecha_hora_evento||context.alert.fecha_hora_correo)){
  if(!dryRun)await store.omit(action,'LIBERACION_HUMANA_PREVALECE');return {outcome:'review',code:'LIBERACION_HUMANA_PREVALECE'};
 }
 if(dryRun)return {outcome:'eligible',code:decision.code};
 if(!settings.enabled)return {outcome:'disabled'};
 if(await store.hourlyAttempts()>=settings.maxPerHour)return {outcome:'limited'};
 const before=await api.find(decision.user);
 if(before&&targetMatches(before,decision.user)){
  await store.omit(action,'YA_BLOQUEADO_EN_API');return {outcome:'already_blocked'};
 }
 // Recheck policy/current source and whitelist immediately before the durable claim.
 const latest=await store.context(action);
 const checked=assessUserAlert(action,latest.alert,latest.evidence,latest.rule,settings,now());
 if(!checked.eligible||checked.evidenceHash!==decision.evidenceHash||await store.protectedUser(decision.user)||await store.unresolved(decision.user,action.accion_id)||await store.releasedSince(decision.user,latest.alert.fecha_hora_evento||latest.alert.fecha_hora_correo)||await store.corroborations(action,latest)<latest.rule.min_alertas){
  await store.omit(action,'CONTEXTO_CAMBIO');return {outcome:'review',code:'CONTEXTO_CAMBIO'};
 }
 const claim=await store.claim(action,{policy:POLICY_VERSION,code:decision.code,evidenceHash:decision.evidenceHash,attemptedAt:new Date(now()).toISOString()});
 if(!claim)return {outcome:'claimed_elsewhere'};
 let receipt;
 try{
  receipt=await api.block(decision.user);
  if(![200,201].includes(receipt.status)||!targetMatches(receipt.data?.bloqueo,decision.user)){
   await store.finish(action,claim,{phase:'outcome_unknown',httpStatus:receipt.status,code:'RESPUESTA_NO_VERIFICADA'});
   return {outcome:'unknown'};
  }
  // Save the receipt before verifying, so a crash cannot erase the acknowledged ID.
  await store.finish(action,claim,{phase:'acknowledged',httpStatus:receipt.status,blockId:receipt.data.bloqueo.id,code:'PENDIENTE_COMPROBACION'});
  const found=await api.find(decision.user);
  if(!targetMatches(found,decision.user)||found.id!==receipt.data.bloqueo.id){
   await store.finish(action,claim,{phase:'outcome_unknown',httpStatus:receipt.status,blockId:receipt.data.bloqueo.id,code:'COMPROBACION_NO_COINCIDE'});
   return {outcome:'unknown'};
  }
  await store.finish(action,claim,{phase:'verified',httpStatus:receipt.status,blockId:found.id,code:'BLOQUEO_VERIFICADO'});
  return {outcome:'verified'};
 }catch{
  // No retry of POST. A database error may prevent this annotation; the committed claim remains.
  await store.finish(action,claim,{phase:'outcome_unknown',httpStatus:receipt?.status??null,code:'REQUIERE_COMPROBACION_MANUAL'}).catch(()=>{});
  return {outcome:'unknown'};
 }
}

export async function runCycle({store,api,settings,dryRun=true,now}){
 const readiness=await store.readiness();
 if(!readiness.ready)return {ready:false,missing:readiness.missing,executed:0};
 if(!await store.lock())return {ready:true,busy:true,executed:0};
 const counts={ready:true,dryRun,examined:0,eligible:0,verified:0,review:0,unknown:0,already_blocked:0};
 try{
  const actions=await store.pending(100);
  let attempts=0;
  for(const action of actions){
   if(!dryRun&&attempts>=settings.maxPerRun)break;
   const result=await processAction(action,{store,api,settings,dryRun,now});counts.examined++;
   if(result.outcome in counts)counts[result.outcome]++;
   if(['verified','unknown'].includes(result.outcome))attempts++;
   if(result.outcome==='unknown'||result.outcome==='limited')break; // Circuit breaker.
  }
  return counts;
 }finally{await store.unlock();}
}
