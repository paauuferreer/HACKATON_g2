import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticate,createHandler,toIncident,readDashboard,checkReadiness} from '../lib/service.mjs';
const env={SOC_BACKEND_TOKEN:'x'.repeat(40),READER_EMAILS:'reader@example.invalid'};
const headers={authorization:`Bearer ${env.SOC_BACKEND_TOKEN}`,'x-soc-actor':'reader@example.invalid'};
test('exige secreto de servidor y actor autorizado; rechaza acceso desde navegador',()=>{
 assert.equal(authenticate(headers,env),'reader@example.invalid');
 for(const h of [{}, {...headers,authorization:'Bearer wrong'}, {...headers,'x-soc-actor':'other@example.invalid'}, {...headers,origin:'https://evil.invalid'}])assert.throws(()=>authenticate(h,env));
});
test('deniega escrituras antes de conectar a PostgreSQL',async()=>{
 let connected=false;const pool={async connect(){connected=true;throw new Error('no debe ejecutarse');}};
 const res={setHeader(){},end(body){this.body=JSON.parse(body);}};
 await createHandler({pool,env})({headers,method:'POST',url:'/soc'},res);
 assert.equal(res.statusCode,405);assert.equal(connected,false);
});
test('no expone credenciales o SQL en errores de conexión',async()=>{
 const res={setHeader(){},end(body){this.body=body;}};
 await createHandler({pool:{async connect(){throw new Error('password=secret query data');}},env})({headers,method:'GET',url:'/soc'},res);
 assert.equal(res.statusCode,503);assert.doesNotMatch(res.body,/secret|query data/);
});
test('mapea la clasificación SQL sin reclasificar por el asunto',()=>{
 const row={alerta_id:'id',asunto_correo:'Ransomware crítico',soc_prioridad:'P4',soc_peligrosidad:'CRITICO',estado:'EN_REVISION',clase_incibe:'Fraude',fecha_hora_correo:'2026-11-03T12:00:00Z'};
 const item=toIncident(row);assert.equal(item.analysis.priority,'Baja');assert.equal(item.analysis.incibeClass,'Fraude');assert.equal(item.analysis.severitySource,'CRITICO');assert.equal(item.status,'En revisión');
});
test('consulta parametrizada y rollback si falla una vista',async()=>{
 const calls=[];const q="x%' OR 1=1 --";
 const client={async query(sql,args){calls.push({sql,args});if(sql.startsWith('SELECT * FROM public.v_alertas'))throw new Error('fallo simulado');return {rows:[]};}};
 await assert.rejects(()=>readDashboard(client,new URL('https://test/soc?q='+encodeURIComponent(q)),'reader@example.invalid',env));
 assert.ok(calls[0].sql.includes('READ ONLY'));assert.equal(calls.at(-1).sql,'ROLLBACK');
 assert.ok(!calls[1].sql.includes(q));assert.deepEqual(calls[1].args,["%x\\%' OR 1=1 --%",0]);
});
test('evidencias pendientes y páginas inválidas no consultan tablas',async()=>{
 const client={async query(){throw new Error('no debe consultar');}};
 for(const suffix of ['?view=evidence&id=id','?offset=-1'])await assert.rejects(()=>readDashboard(client,new URL('https://test/soc'+suffix),'reader@example.invalid',env),e=>[400,503].includes(e.status));
});
test('readiness distingue lectura de preparación para producción',async()=>{
 const result=await checkReadiness({async query(){return {rows:[]};}});
 assert.equal(result.productionReady,false);assert.equal(result.dashboardReady,false);assert.ok(result.missingViews.includes('v_alertas'));
});
