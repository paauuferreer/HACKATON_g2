import test from 'node:test';
import assert from 'node:assert/strict';
import {main} from '../soc/run-automation.mjs';
test('sin clave queda esperando sin acceder a PostgreSQL',async()=>{const r=await main({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_POLICY:'sql'},[]);assert.equal(r.waitingForCredential,true);assert.equal(r.executed,0);});
test('401 no consume la cola ni abre PostgreSQL',async()=>{const saved=globalThis.fetch;let calls=0;globalThis.fetch=async(url,options)=>{calls++;assert.equal(options.method,'GET');return new Response(JSON.stringify({detail:'denegado'}),{status:401});};try{const r=await main({BLOQUEO_AUTO_ACTIVO:'1',AUTOMATION_POLICY:'sql',BLOCK_API_KEY:'synthetic-test-only'},[]);assert.equal(r.waitingForCredential,true);assert.equal(calls,1);}finally{globalThis.fetch=saved;}});
