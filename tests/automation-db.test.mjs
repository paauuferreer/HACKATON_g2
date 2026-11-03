import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {runtimeSettings} from '../soc/automation-policy.mjs';
import {processAction} from '../soc/automation-engine.mjs';

if(!process.env.TEST_PG_URL){test('PostgreSQL aislado: ejecutar en CI con TEST_PG_URL', {skip:true},()=>{});}
else{
 const url=new URL(process.env.TEST_PG_URL);
 if(!['localhost','127.0.0.1'].includes(url.hostname)||url.pathname!=='/automation_test')throw new Error('Estas pruebas solo admiten localhost/automation_test');
 const {default:pg}=await import('pg');
 const {postgresStore}=await import('../soc/automation-store.mjs');
 test('PostgreSQL real aislado: transacciones, reinicio y exclusión mutua',async t=>{
  const client=new pg.Client({connectionString:url.href}),second=new pg.Client({connectionString:url.href});
  await client.connect();await second.connect();
  try{
   await client.query(`
    CREATE TYPE test_prioridad AS ENUM ('P1','P4');
    CREATE TYPE test_peligrosidad AS ENUM ('CRITICO','BAJO');
    CREATE TABLE acciones_bloqueo (accion_id uuid PRIMARY KEY,accion text,usuario_objetivo text,ip_objetivo inet,motivo text,alerta_id uuid,regla text,solicitado_por text,estado text,origen text,simulacion boolean DEFAULT false,fecha_solicitud timestamptz DEFAULT now(),fecha_respuesta timestamptz,http_status int,respuesta_api jsonb,exito boolean);
    CREATE TABLE lista_blanca (tipo text,usuario text,activo boolean);
    CREATE TABLE reglas_bloqueo_auto (regla_id text PRIMARY KEY,activa boolean,objetivo text,prioridades test_prioridad[],peligrosidades test_peligrosidad[],clases_incibe text[],min_alertas int,ventana_minutos int);
    CREATE TABLE test_alertas (alerta_id uuid,correo_id uuid,usuario_implicado text,equipo_afectado text,soc_prioridad text,soc_peligrosidad text,incibe_clase_id text,estado text,es_sospechosa boolean,remitente_confianza boolean,inconsistencias text[],remitente_correo text,asunto_correo text,titulo text,id_alerta_soc text,id_solicitud text,fecha_hora_correo timestamptz,fecha_hora_evento timestamptz,fecha_ultimo_evento timestamptz);
    CREATE VIEW v_alertas AS SELECT * FROM test_alertas;
    CREATE TABLE test_evidencias (correo_id uuid,remitente_correo text,cuerpo_correo_raw text,eml_raw text,cabeceras jsonb,autenticacion_verificada boolean,autenticacion_metodo text,autenticacion_emisor text);
    CREATE VIEW v_evidencias_automatizacion AS SELECT * FROM test_evidencias;
   `);
   const settings=runtimeSettings({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_START_AT:new Date(Date.now()-900000).toISOString()});
   const store=postgresStore(client,settings),other=postgresStore(second,settings);
   async function seed(){
    await client.query('TRUNCATE acciones_bloqueo,lista_blanca,reglas_bloqueo_auto,test_alertas,test_evidencias');
    const alert=randomUUID(),mail=randomUUID(),id=randomUUID(),date=new Date(Date.now()-60000).toISOString();
    const subject='[SOC] Compromiso confirmado AL-20261103-0001';
    const body='Compromiso confirmado en pc-madrid-001. Cuenta relacionada: ana.perez@sampol.com. Referencia AL-20261103-0001.';
    const eml=`From: soc-hackaton@sampol.com\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`;
    await client.query("INSERT INTO reglas_bloqueo_auto VALUES ('AUTO-01',true,'USUARIO','{P1}','{CRITICO}','{INTRUSION}',1,30)");
    await client.query("INSERT INTO test_alertas VALUES ($1,$2,'ana.perez@sampol.com','pc-madrid-001','P1','CRITICO','INTRUSION','NUEVA',false,true,'{}','soc-hackaton@sampol.com',$3,'Compromiso confirmado','AL-20261103-0001',null,$4,$4,$4)",[alert,mail,subject,date]);
    await client.query("INSERT INTO test_evidencias VALUES ($1,'soc-hackaton@sampol.com',$2,$3,$4,true,'test-gateway','test-source')",[mail,body,eml,JSON.stringify({eml_encoding:'utf8',eml_sha256:createHash('sha256').update(eml).digest('hex')})]);
    await client.query("INSERT INTO acciones_bloqueo (accion_id,accion,usuario_objetivo,alerta_id,regla,estado,origen,fecha_solicitud) VALUES ($1,'BLOQUEAR','ana.perez@sampol.com',$2,'AUTO-01','PENDIENTE','AUTOMATICO',$3)",[id,alert,date]);
    return (await store.pending(1))[0];
   }
   await t.test('lee arrays enum y original MIME; dry-run no muta la cola',async()=>{
    const action=await seed();assert.equal((await store.readiness()).ready,true);
    await client.query('BEGIN READ ONLY');
    try{assert.equal((await processAction(action,{store,settings,dryRun:true,api:{}})).outcome,'eligible');}finally{await client.query('ROLLBACK');}
    assert.equal((await client.query('SELECT estado FROM acciones_bloqueo')).rows[0].estado,'PENDIENTE');
   });
   await t.test('dos procesos no adquieren el mismo lock',async()=>{
    assert.equal(await store.lock(),true);assert.equal(await other.lock(),false);await store.unlock();assert.equal(await other.lock(),true);await other.unlock();
   });
   await t.test('claim visible desde otra conexión antes de POST; timeout queda en ERROR',async()=>{
    const action=await seed();let durable=false;
    const api={find:async()=>null,block:async()=>{const row=(await second.query('SELECT estado,respuesta_api FROM acciones_bloqueo WHERE accion_id=$1',[action.accion_id])).rows[0];durable=row.estado==='ERROR'&&row.respuesta_api.automation.phase==='outcome_unknown';throw new Error('timeout simulado');}};
    assert.equal((await processAction(action,{store,settings,api,dryRun:false})).outcome,'unknown');
    assert.equal(durable,true,'La intención debe estar confirmada y visible antes del POST');
    assert.equal(await store.hourlyAttempts(),1);
    const id=randomUUID();await client.query("INSERT INTO acciones_bloqueo (accion_id,accion,usuario_objetivo,alerta_id,regla,estado,origen) VALUES ($1,'BLOQUEAR','ana.perez@sampol.com',$2,'AUTO-01','PENDIENTE','AUTOMATICO')",[id,action.alerta_id]);
    const next=(await store.pending(1))[0];assert.equal((await processAction(next,{store,settings,api,dryRun:false})).code,'RESULTADO_PREVIO_DESCONOCIDO');
   });
   await t.test('respuesta y consulta verificadas persisten el éxito y su política',async()=>{
    const action=await seed();let reads=0;const record={id:55,equipo_id:2,tipo:'usuario',valor:action.usuario_objetivo,activo:true};
    const api={find:async()=>reads++?record:null,block:async()=>({status:201,data:{bloqueo:record}})};
    assert.equal((await processAction(action,{store,settings,api,dryRun:false})).outcome,'verified');
    const row=(await client.query('SELECT * FROM acciones_bloqueo WHERE accion_id=$1',[action.accion_id])).rows[0];assert.equal(row.estado,'EJECUTADA');assert.equal(row.exito,true);assert.equal(row.respuesta_api.automation.phase,'verified');assert.equal(row.respuesta_api.automation.blockId,55);
   });
  }finally{await client.end();await second.end();}
 });
}
