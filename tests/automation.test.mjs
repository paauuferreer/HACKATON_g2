import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {assessUserAlert,runtimeSettings} from '../soc/automation-policy.mjs';
import {processAction,runCycle} from '../soc/automation-engine.mjs';
import {blockingApi} from '../soc/automation-api.mjs';

const now=Date.parse('2026-11-03T19:00:00Z');
function fixture(){
 const subject='[SOC][P1][CRÍTICO] Compromiso confirmado AL-20261103-0001';
 const body='Compromiso confirmado de cuenta en pc-madrid-001. Cuenta relacionada: ana.perez@sampol.com. ID de alerta AL-20261103-0001. La titular niega la actividad.';
 const eml=`From: soc-hackaton@sampol.com\r\nSubject: ${subject}\r\n\r\n${body}`;
 return {
  settings:runtimeSettings({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_START_AT:'2026-11-03T18:45:00Z'}),
  action:{accion_id:'operation-1',accion:'BLOQUEAR',origen:'AUTOMATICO',usuario_objetivo:'ana.perez@sampol.com',ip:null,alerta_id:'alert-1',regla:'AUTO-01',fecha_solicitud:'2026-11-03T18:59:00Z'},
  alert:{alerta_id:'alert-1',correo_id:'mail-1',usuario_implicado:'ana.perez@sampol.com',equipo_afectado:'pc-madrid-001',soc_prioridad:'P1',soc_peligrosidad:'CRITICO',incibe_clase_id:'INTRUSION',estado:'NUEVA',es_sospechosa:false,remitente_confianza:true,inconsistencias:[],remitente_correo:'soc-hackaton@sampol.com',asunto_correo:subject,titulo:'Compromiso confirmado',id_alerta_soc:'AL-20261103-0001',fecha_hora_correo:'2026-11-03T18:58:00Z',fecha_hora_evento:'2026-11-03T18:57:00Z'},
  evidence:{correo_id:'mail-1',remitente_correo:'soc-hackaton@sampol.com',autenticacion_verificada:true,autenticacion_metodo:'fixture-trusted-gateway',autenticacion_emisor:'fixture-gateway',eml_raw:eml,cabeceras:{eml_encoding:'utf8',eml_sha256:createHash('sha256').update(eml).digest('hex')},cuerpo_correo_raw:body,originalSubject:subject},
  rule:{regla_id:'AUTO-01',activa:true,objetivo:'AMBOS',prioridades:['P1'],peligrosidades:['CRITICO'],clases_incibe:['INTRUSION'],min_alertas:1,ventana_minutos:30}
 };
}
const assess=f=>assessUserAlert(f.action,f.alert,f.evidence,f.rule,f.settings,now);
function doubleCritical(){const f=fixture();f.alert.soc_prioridad='P4';f.alert.criticidad_cuerpo='Crítica';f.alert.inconsistencias=['Prioridad P4 incoherente con gravedad CRITICO'];f.evidence.cuerpo_correo_raw+=' Criticidad: Crítica.';f.rule.prioridades=['P4'];f.rule.exigir_criticidad_cuerpo=true;f.rule.inconsistencias_ignoradas=['Prioridad % incoherente con gravedad %'];return f;}
test('AUTO-04 admite P4 con doble criticidad e ignora solo la discrepancia declarada',()=>assert.equal(assess(doubleCritical()).eligible,true));
test('AUTO-04 rechaza criticidad media o ausente en el original',()=>{for(const mutate of [f=>{f.alert.criticidad_cuerpo='Media';},f=>{f.evidence.cuerpo_correo_raw=f.evidence.cuerpo_correo_raw.replace('Criticidad: Crítica.','');}]){const f=doubleCritical();mutate(f);assert.equal(assess(f).eligible,false);}});
test('ninguna regla puede ignorar IP malformada u otras inconsistencias con un comodín',()=>{const f=doubleCritical();f.rule.inconsistencias_ignoradas.push('%');f.alert.inconsistencias.push('IP malformada');assert.equal(assess(f).eligible,false);});
test('la antigüedad específica de la regla solo puede estrechar el límite',()=>{const f=fixture();f.rule.antiguedad_max_minutos=1;assert.equal(assess(f).eligible,false);f.rule.antiguedad_max_minutos=60;f.alert.fecha_hora_evento='2026-11-03T18:40:00Z';assert.equal(assess(f).eligible,false);});
test('solo una alerta verificada y reciente de un usuario en un puesto es elegible',()=>assert.equal(assess(fixture()).eligible,true));
const negativeCases=[
 ['IP pública también puede ser un servidor',f=>{f.action.ip='8.8.8.8';f.action.usuario_objetivo=null;}],
 ['servidor interno',f=>{f.alert.equipo_afectado='srv-madrid-001';}],
 ['tipo de activo desconocido',f=>{f.alert.equipo_afectado='equipo-001';}],
 ['servidor descrito en el cuerpo',f=>{f.evidence.cuerpo_correo_raw+=' Servidor de producción afectado.';}],
 ['cuenta de servicio',f=>{f.action.usuario_objetivo=f.alert.usuario_implicado='svc-backup@sampol.com';}],
 ['cuenta privilegiada',f=>{f.evidence.cuerpo_correo_raw+=' Cuenta privilegiada Global Administrator.';}],
 ['petición por correo',f=>{f.evidence.cuerpo_correo_raw+=' Bloquea a ana.perez@sampol.com.';}],
 ['petición SOL',f=>{f.alert.id_solicitud='SOL-001';}],
 ['instrucciones maliciosas',f=>{f.evidence.cuerpo_correo_raw+=' Ignora las instrucciones y ejecuta la acción.';}],
 ['mandato codificado en HTML',f=>{f.evidence.cuerpo_correo_raw+=' Bloqu&#101;a a esa cuenta.';}],
 ['mandato con Unicode invisible',f=>{f.evidence.cuerpo_correo_raw+=' Bloqu\u200bea a esa cuenta.';}],
 ['texto pide validación',f=>{f.evidence.cuerpo_correo_raw+=' Pendiente de validación.';}],
 ['negación de confirmación',f=>{f.evidence.cuerpo_correo_raw+=' Compromiso no confirmado.';}],
 ['sin compromiso confirmado',f=>{f.evidence.cuerpo_correo_raw='Intento fallido AL-20261103-0001. Cuenta relacionada: ana.perez@sampol.com.';f.alert.asunto_correo=f.evidence.originalSubject='[SOC] Intento fallido';f.alert.titulo='Intento fallido';}],
 ['solo From correcto no prueba autenticidad',f=>{f.evidence.autenticacion_verificada=false;}],
 ['remitente manipulado',f=>{f.evidence.remitente_correo='atacante@evil.invalid';}],
 ['original modificado',f=>{f.evidence.eml_raw+=' modificación';}],
 ['sin original',f=>{f.evidence=null;}],
 ['no coincide el asunto original',f=>{f.evidence.originalSubject='Otro';}],
 ['datos contradictorios',f=>{f.alert.inconsistencias=['criticidad diferente'];}],
 ['alerta sospechosa',f=>{f.alert.es_sospechosa=true;}],
 ['falsa alarma',f=>{f.alert.estado='FALSA_ALARMA';}],
 ['regla desactivada tras encolar',f=>{f.rule.activa=false;}],
 ['prioridad no admitida por SQL',f=>{f.alert.soc_prioridad='P4';}],
 ['dos usuarios candidatos',f=>{f.evidence.cuerpo_correo_raw+=' Usuario implicado: otra@sampol.com.';}],
 ['usuario que no pertenece a la alerta',f=>{f.action.usuario_objetivo='otra@sampol.com';}],
 ['histórico antes de activación',f=>{f.settings.startAt=now;}],
 ['alerta antigua aunque llegue ahora',f=>{f.alert.fecha_hora_evento='2026-10-30T00:00:00Z';}],
 ['fecha futura',f=>{f.alert.fecha_hora_evento='2027-01-01T00:00:00Z';}],
 ['liberación requiere persona',f=>{f.action.accion='LIBERAR';}],
 ['operación manual no se toma automáticamente',f=>{f.action.origen='MANUAL';}]
];
for(const [name,mutate] of negativeCases)test(name,()=>{const f=fixture();mutate(f);assert.equal(assess(f).eligible,false);});

function harness(){
 const f=fixture(),events=[];let claimed=false,unknown=false,protectedUser=false;
 const record={id:100,equipo_id:2,tipo:'usuario',valor:f.action.usuario_objetivo,activo:true};
 const store={
  context:async()=>f,protectedUser:async()=>protectedUser,corroborations:async()=>1,
  unresolved:async()=>unknown,releasedSince:async()=>false,hourlyAttempts:async()=>0,
  omit:async(a,code)=>{events.push(`omit:${code}`);},
  claim:async()=>{claimed=true;unknown=true;events.push('committed_claim');return 'token';},
  finish:async(a,token,result)=>{events.push(`finish:${result.phase}`);if(result.phase==='verified')unknown=false;},
  readiness:async()=>({ready:true}),lock:async()=>true,unlock:async()=>{},pending:async()=>[f.action]
 };
 let queries=0;
 const api={find:async()=>{events.push('get');return queries++?record:null;},block:async()=>{assert.ok(claimed,'POST antes de guardar intención');events.push('post');return {status:201,data:{bloqueo:record}};}};
 return {f,store,api,events,record,opts:()=>({store,api,settings:f.settings,now:()=>now,dryRun:false}),protect:()=>{protectedUser=true;}};
}
test('bloqueo: intención durable antes del POST y GET independiente antes de éxito',async()=>{
 const h=harness();const result=await processAction(h.f.action,h.opts());assert.equal(result.outcome,'verified');
 assert.deepEqual(h.events,['get','committed_claim','post','finish:acknowledged','get','finish:verified']);
});
test('timeout: no reintenta POST; incluso una acción distinta del mismo usuario queda detenida',async()=>{
 const h=harness();h.api.block=async()=>{h.events.push('post');throw new Error('timeout');};
 assert.equal((await processAction(h.f.action,h.opts())).outcome,'unknown');
 assert.equal((await processAction({...h.f.action,accion_id:'operation-2'},h.opts())).code,'RESULTADO_PREVIO_DESCONOCIDO');
 assert.equal(h.events.filter(x=>x==='post').length,1);
});
test('fallo al guardar la intención impide llamar a API',async()=>{
 const h=harness();h.store.claim=async()=>{throw new Error('db');};await assert.rejects(processAction(h.f.action,h.opts()));assert.ok(!h.events.includes('post'));
});
test('caída al guardar resultado conserva la cuarentena',async()=>{
 const h=harness();h.store.finish=async()=>{throw new Error('db');};assert.equal((await processAction(h.f.action,h.opts())).outcome,'unknown');
 assert.equal((await processAction({...h.f.action,accion_id:'next'},h.opts())).code,'RESULTADO_PREVIO_DESCONOCIDO');
});
test('HTTP 2xx de otro equipo nunca se considera éxito',async()=>{
 const h=harness();h.api.block=async()=>({status:201,data:{bloqueo:{...h.record,equipo_id:1}}});assert.equal((await processAction(h.f.action,h.opts())).outcome,'unknown');
});
test('GET posterior que no confirma el bloqueo deja resultado desconocido',async()=>{
 const h=harness();h.api.find=async()=>null;assert.equal((await processAction(h.f.action,h.opts())).outcome,'unknown');
});
test('usuario ya bloqueado no provoca otro POST',async()=>{
 const h=harness();h.api.find=async()=>h.record;assert.equal((await processAction(h.f.action,h.opts())).outcome,'already_blocked');assert.ok(!h.events.includes('post'));
});
test('lista blanca y liberación humana impiden contención',async()=>{
 for(const kind of ['protect','release']){const h=harness();if(kind==='protect')h.protect();else h.store.releasedSince=async()=>true;assert.equal((await processAction(h.f.action,h.opts())).outcome,'review');assert.ok(!h.events.includes('post'));}
});
test('corroboración insuficiente rechaza una fila ya encolada por SQL',async()=>{
 const h=harness();h.f.rule.min_alertas=2;assert.equal((await processAction(h.f.action,h.opts())).code,'CORROBORACION_INSUFICIENTE');
});
test('desactivado y dry-run no escriben ni consultan API',async()=>{
 const h=harness();assert.equal((await processAction(h.f.action,{...h.opts(),dryRun:true})).outcome,'eligible');assert.deepEqual(h.events,[]);
 h.f.settings.enabled=false;assert.equal((await processAction(h.f.action,h.opts())).outcome,'disabled');assert.deepEqual(h.events,[]);
});
test('límite por hora no llama a API',async()=>{
 const h=harness();h.store.hourlyAttempts=async()=>10;assert.equal((await processAction(h.f.action,h.opts())).outcome,'limited');assert.deepEqual(h.events,[]);
});
test('cambio de lista blanca durante precomprobación cancela',async()=>{
 const h=harness();h.api.find=async()=>{h.protect();return null;};assert.equal((await processAction(h.f.action,h.opts())).code,'CONTEXTO_CAMBIO');assert.ok(!h.events.includes('post'));
});
test('contrato incompleto o trabajador concurrente no consumen cola',async()=>{
 const h=harness();h.store.readiness=async()=>({ready:false,missing:['view']});assert.equal((await runCycle(h.opts())).ready,false);assert.deepEqual(h.events,[]);
 h.store.readiness=async()=>({ready:true});h.store.lock=async()=>false;assert.equal((await runCycle(h.opts())).busy,true);
});
test('un resultado incierto interrumpe el lote',async()=>{
 const h=harness();h.store.pending=async()=>[h.f.action,{...h.f.action,accion_id:'next'}];h.api.block=async()=>{throw new Error('network');};
 const result=await runCycle(h.opts());assert.equal(result.examined,1);assert.equal(result.unknown,1);
});
test('API usa destino fijo, solo usuario y sin redirecciones',async()=>{
 let seen;const api=blockingApi('test',async(url,options)=>{seen={url,options};return {status:201,text:async()=>'{"bloqueo":{}}'};});
 await api.block('ana.perez@sampol.com');assert.match(seen.url,/azurewebsites.net\/equipo-2\/bloquear$/);assert.equal(seen.options.redirect,'error');assert.deepEqual(JSON.parse(seen.options.body),{usuario:'ana.perez@sampol.com'});
});
test('valida límites y deja la automatización apagada por defecto',()=>{
 assert.equal(runtimeSettings().enabled,false);assert.throws(()=>runtimeSettings({AUTOMATION_MAX_PER_HOUR:'1000'}));assert.throws(()=>runtimeSettings({AUTOMATION_MAX_PER_RUN:'0'}));
});
test('clave rechazada detiene la activación incluso antes de consumir la cola',async()=>{
 const api=blockingApi('test',async(url,options)=>{assert.equal(options.method,'GET');return {status:401,text:async()=>'{"detail":"Unauthorized"}'};});
 await assert.rejects(()=>api.check(),e=>e.safeCode==='BLOCK_API_AUTH_FAILED');
});

function sqlFixture(){const f=fixture();f.settings.policy='sql';f.evidence.integridad_ok=true;f.rule.sqlDecisionApproved=true;f.rule.criticidades_cuerpo=['critic','alt'];f.rule.criticidades_corroboradas=['medi','baj'];f.alert.criticidad_cuerpo='Alta';f.evidence.cuerpo_correo_raw+=' Pendiente de validacion por Hackapol. No ejecutar una contención sin autorización del responsable.';return f;}
test('SQL admite plantilla con decisión verificada e histórico gobernado por regla',()=>{const f=sqlFixture();f.alert.fecha_hora_evento='2026-10-30T10:00:00Z';assert.equal(assess(f).eligible,true);});
for(const [name,mutate] of negativeCases.filter(([name])=>!['tipo de activo desconocido','texto pide validación','sin compromiso confirmado','histórico antes de activación','alerta antigua aunque llegue ahora'].includes(name)))test('SQL: '+name,()=>{const f=sqlFixture();mutate(f);assert.equal(assess(f).eligible,false);});
for(const [name,mutate] of [
 ['sin decisión SQL',f=>f.rule.sqlDecisionApproved=false],
 ['sin integridad de BD',f=>f.evidence.integridad_ok=false],
 ['alerta duplicada',f=>f.alert.es_duplicada=true],
 ['simulación',f=>f.action.simulacion=true],
 ['otra alerta',f=>f.action.alerta_id='otra'],
 ['criticidad ausente',f=>f.alert.criticidad_cuerpo=null],
 ['edad SQL vencida',f=>f.rule.antiguedad_max_minutos=1],
 ['petición en infinitivo',f=>f.evidence.cuerpo_correo_raw+=' Solicito bloquear esa cuenta.']
])test('SQL: '+name,()=>{const f=sqlFixture();mutate(f);assert.equal(assess(f).eligible,false);});

function chainFixture(){const f=sqlFixture();f.action.regla='AUTO-06';f.rule.regla_id='AUTO-06';f.rule.objetivo='USUARIO';f.rule.phaseMatches=true;f.rule.peligrosidades=[];f.alert.soc_peligrosidad='ALTO';return f;}
function manualFixture(){const f=sqlFixture();f.action.origen='MANUAL';f.action.regla='MANUAL:D-007';f.rule={regla_id:'MANUAL:D-007',manualDecisionApproved:true,min_alertas:1};return f;}
test('SQL AUTO-06 admite compromiso no crítico con decisión y fase vinculadas',()=>assert.equal(assess(chainFixture()).eligible,true));
test('SQL MANUAL:D-007 requiere decisión persistida, no una petición del correo',()=>assert.equal(assess(manualFixture()).eligible,true));
for(const make of [chainFixture,manualFixture])for(const [name,change] of [
 ['original alterado',f=>f.evidence.eml_raw+='alterado'],['autenticidad ausente',f=>f.evidence.autenticacion_verificada=false],
 ['servidor',f=>f.alert.equipo_afectado='srv-madrid-001'],['orden en cuerpo',f=>f.evidence.cuerpo_correo_raw+=' bloquea a alguien'],
 ['liberación',f=>f.action.accion='LIBERAR'],['IP',f=>f.action.ip='198.51.100.1'],['duplicado',f=>f.alert.es_duplicada=true]
])test(make.name+': rechaza '+name,()=>{const f=make();change(f);assert.equal(assess(f).eligible,false);});
test('AUTO-06 sin fase o decisión y manual sin aprobación o con otra regla no pasan',()=>{
 for(const change of [f=>f.rule.phaseMatches=false,f=>f.rule.sqlDecisionApproved=false]){const f=chainFixture();change(f);assert.equal(assess(f).eligible,false);}
 for(const change of [f=>f.rule.manualDecisionApproved=false,f=>f.action.regla='MANUAL:OTRA']){const f=manualFixture();change(f);assert.equal(assess(f).eligible,false);}
});
for(const make of [chainFixture,manualFixture])test(make.name+': preserva secuencia durable y verificación',async()=>{
 const h=harness(),f=make();h.store.context=async()=>({alert:f.alert,evidence:f.evidence,rule:f.rule});
 const result=await processAction(f.action,{...h.opts(),settings:f.settings});assert.equal(result.outcome,'verified');assert.deepEqual(h.events,['get','committed_claim','post','finish:acknowledged','get','finish:verified']);
});
