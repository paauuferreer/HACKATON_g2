import test from 'node:test';
import assert from 'node:assert/strict';
import {main} from '../soc/run-automation.mjs';
test('sin clave queda esperando sin acceder a PostgreSQL',async()=>{const r=await main({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_POLICY:'sql'},[]);assert.equal(r.waitingForCredential,true);assert.equal(r.executed,0);});
test('401 no consume la cola ni abre PostgreSQL',async()=>{const saved=globalThis.fetch;let calls=0;globalThis.fetch=async(url,options)=>{calls++;assert.equal(options.method,'GET');return new Response(JSON.stringify({detail:'denegado'}),{status:401});};try{const r=await main({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_POLICY:'sql',BLOCK_API_KEY:'synthetic-test-only'},[]);assert.equal(r.waitingForCredential,true);assert.equal(calls,1);}finally{globalThis.fetch=saved;}});

// Exercise MIME parsing and corroboration in the store, not just policy flags.
import {postgresStore} from '../soc/automation-store.mjs';
import {runtimeSettings} from '../soc/automation-policy.mjs';
import {createHash} from 'node:crypto';
test('AUTO-06 only counts distinct authenticated prior phases',async()=>{
 const user='ana.perez@sampol.com',time=new Date(Date.now()-60000).toISOString();
 const subject='[SOC] Phishing AL-TEST-0001';const body=`Cuenta relacionada: ${user}. ID de alerta AL-TEST-0001.`;
 const eml=`From: soc-hackaton@sampol.com\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`;
 const prior={alerta_id:'prior',correo_id:'mail',usuario_implicado:user,equipo_afectado:'pc-madrid-001',fase:'ACCESO_INICIAL',estado:'NUEVA',es_sospechosa:false,remitente_confianza:true,remitente_correo:'soc-hackaton@sampol.com',asunto_correo:subject,titulo:'Phishing',id_alerta_soc:'AL-TEST-0001',fecha_hora_correo:time,fecha_hora_evento:time};
 const evidence={correo_id:'mail',remitente_correo:'soc-hackaton@sampol.com',integridad_ok:true,autenticacion_verificada:true,autenticacion_metodo:'test',autenticacion_emisor:'test',eml_raw:eml,cabeceras:{eml_encoding:'utf8',eml_sha256:createHash('sha256').update(eml).digest('hex')}};
 const client={async query(sql){return {rows:sql.includes('v_evidencias_automatizacion')?[evidence]:[prior,{...prior,alerta_id:'duplicate'}]};}};
 const store=postgresStore(client,runtimeSettings({AUTOMATION_POLICY:'sql'}));
 const action={accion:'BLOQUEAR',origen:'AUTOMATICO',regla:'AUTO-06',usuario_objetivo:user,alerta_id:'primary',fecha_solicitud:time};
 const context={alert:{id_alerta_soc:'AL-TEST-0002',fecha_hora_evento:time,fecha_hora_correo:time},rule:{regla_id:'AUTO-06',activa:true,objetivo:'USUARIO',sqlDecisionApproved:true,min_fases_previas:1,ventana_minutos:120,fases_previas:['ACCESO_INICIAL','CREDENCIALES']}};
 assert.equal(await store.corroborations(action,context),1);
 evidence.autenticacion_verificada=false;assert.equal(await store.corroborations(action,context),0);
 evidence.autenticacion_verificada=true;evidence.eml_raw+='tampered';assert.equal(await store.corroborations(action,context),0);
});
test('manual context requires persisted matching decision, human actor and reason',async()=>{
 let row;const client={async query(sql,args){if(sql.includes('v_alertas'))return {rows:[]};assert.deepEqual(args,['operation','alert','ana.perez@sampol.com']);return {rows:row?[row]:[]};}};
 const store=postgresStore(client,runtimeSettings({AUTOMATION_POLICY:'sql'}));const action={accion_id:'operation',alerta_id:'alert',usuario_objetivo:'ana.perez@sampol.com',origen:'MANUAL',regla:'MANUAL:D-007'};
 assert.equal((await store.context(action)).rule.manualDecisionApproved,false);
 row={solicitado_por:'responsable',motivo:'Decisión validada'};assert.equal((await store.context(action)).rule.manualDecisionApproved,true);
 row.solicitado_por='AUTO:A';assert.equal((await store.context(action)).rule.manualDecisionApproved,false);
 row.solicitado_por='responsable';row.motivo='';assert.equal((await store.context(action)).rule.manualDecisionApproved,false);
});
test('403 also waits without opening PostgreSQL or consuming pending actions',async()=>{const saved=globalThis.fetch;globalThis.fetch=async()=>new Response('{}',{status:403});try{const r=await main({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_POLICY:'sql',BLOCK_API_KEY:'synthetic-test-only'},[]);assert.equal(r.waitingForCredential,true);assert.equal(r.executed,0);}finally{globalThis.fetch=saved;}});
