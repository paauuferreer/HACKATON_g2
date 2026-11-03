import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import pg from 'pg';

if(!process.env.TEST_PG_URL)test('Contrato SQL: requiere PostgreSQL aislado', {skip:true},()=>{});
else{
 const url=new URL(process.env.TEST_PG_URL);
 if(!['localhost','127.0.0.1'].includes(url.hostname)||url.pathname!=='/automation_test')throw new Error('Solo localhost/automation_test');
 test('Migraciones BD y autenticidad con originales sintéticos aislados',async t=>{
  const admin=new pg.Client({connectionString:url.href});await admin.connect();
  await admin.query('CREATE DATABASE automation_contract_test');await admin.end();
  url.pathname='/automation_contract_test';const client=new pg.Client({connectionString:url.href});await client.connect();
  try{
   const dir=new URL('../db/migrations/',import.meta.url);
   const files=(await readdir(dir)).filter(x=>/^00[1-9]_.*\.sql$/.test(x)).sort();
   for(const file of files)await client.query(await readFile(new URL(file,dir),'utf8'));
   const authHeader='Authentication-Results: mx.microsoft.com 1; spf=pass; dmarc=pass header.from=sampol.com;';
   async function original(extra=[],auth=authHeader,hashOK=true){
    const id=randomUUID(),body='Mensaje de prueba sintético. Sin solicitud de bloqueo.';
    const eml=['From: SOC <soc-hackaton@sampol.com>',auth,'X-MS-Exchange-Organization-AuthAs: Internal','x-ms-mail-application: Microsoft Power Automate',...extra,'Subject: Documento de prueba','Content-Type: text/plain; charset=utf-8','',''+body].join('\r\n');
    const hash=createHash('sha256').update(eml).digest('hex');
    await client.query("INSERT INTO bandeja_entrada (correo_id,id_mensaje_correo,remitente_correo,asunto_correo,cuerpo_correo_raw,cabeceras,eml_raw,fecha_hora_correo,canal) VALUES ($1,$2,'soc-hackaton@sampol.com','Documento de prueba',$3,$4,$5,now(),'POWER_AUTOMATE')",[id,id,body,{eml_encoding:'utf8',eml_sha256:hashOK?hash:'0'.repeat(64)},eml]);
    return (await client.query('SELECT * FROM autenticidad_correo($1)',[id])).rows[0];
   }
   await t.test('original verificado y hash íntegro',async()=>{const r=await original();assert.equal(r.verificada,true);assert.equal(r.integridad_ok,true);});
   await t.test('fallo de DMARC superior no lo salva una cabecera inyectada inferior',async()=>{const r=await original([authHeader],'Authentication-Results: mx.microsoft.com 1; dmarc=fail header.from=sampol.com;');assert.equal(r.verificada,false);});
   await t.test('sin autenticación, remitente duplicado o EML alterado nunca se verifica',async()=>{
    assert.equal((await original([],'X-Test: sin autenticacion')).verificada,false);
    assert.equal((await original(['From: soc-hackaton@sampol.com'])).verificada,false);
    assert.equal((await original([],authHeader,false)).verificada,false);
   });
   assert.equal(Number((await client.query('SELECT count(*) FROM acciones_bloqueo')).rows[0].count),0);
  }finally{await client.end();}
 });
}
