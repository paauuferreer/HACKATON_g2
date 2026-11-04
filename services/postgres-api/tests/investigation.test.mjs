import test from 'node:test';
import assert from 'node:assert/strict';
import {costSnapshot,readChain} from '../lib/investigation.mjs';
test('costes conserva importes generados y excluye datos personales',()=>{
 const row={escenario:'Medio',horas_parada:4,parada:1,respuesta:2,restauracion:3,externos:4,comunicacion:5,total:15,evitado_auto06:6};
 const result=costSnapshot({generado:'04/11/2026 05:16',coste:[row,row,row],victimas:['privado']});
 assert.equal(result.scenarios[0].total,15);assert.equal(result.estimated,true);assert.ok(!JSON.stringify(result).includes('privado'));
 assert.throws(()=>costSnapshot({generado:'fecha',coste:[row]}));
});
test('cadena pagina en servidor, usa vistas, parámetros y transacción de lectura',async()=>{
 const calls=[];const client={async query(sql,args){calls.push([sql,args]);return {rows:sql.includes('FROM public.v_cadena_victimas')?[{victima:"a'@test",orden_victima:1}]:[]};}};
 const result=await readChain(client,new URL('https://test/soc?offset=50'));
 assert.equal(result.victims.length,1);assert.equal(result.hasMore,false);
 assert.deepEqual(calls[1][1],[51,50]);assert.deepEqual(calls[2][1],[["a'@test"]]);assert.match(calls[0][0],/READ ONLY/);assert.equal(calls.at(-1)[0],'COMMIT');
 assert.ok(!calls.some(([sql])=>sql.includes("a'@test")));
});
test('cadena hace rollback ante contrato ausente',async()=>{
 const calls=[];await assert.rejects(()=>readChain({async query(sql){calls.push(sql);if(sql.includes('FROM'))throw Error('missing view');return {rows:[]}}},new URL('https://test/soc')));
 assert.equal(calls.at(-1),'ROLLBACK');
});
