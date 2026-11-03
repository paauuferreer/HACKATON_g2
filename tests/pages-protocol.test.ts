import test from 'node:test';import assert from 'node:assert/strict';import {allowedRequest} from '../lib/pages-protocol';
test('panel externo permite lectura, evidencia y revisión, sin exportar secretos',()=>{
 assert.equal(allowedRequest('/api/soc?q=usuario&offset=0','GET',undefined),true);
 assert.equal(allowedRequest('/api/soc?view=evidence&id=123','GET',undefined),true);
 assert.equal(allowedRequest('/api/soc?view=ip-activity&from=2026-11-01&to=2026-11-03&ip=2001%3Adb8%3A%3A1&basis=event','GET',undefined),true);
 assert.equal(allowedRequest('/api/soc','POST',JSON.stringify({action:'review'})),true);
 assert.equal(allowedRequest('/api/soc','POST',JSON.stringify({action:'connectionSecret'})),false);
 for(const path of ['https://evil.example/api/soc','//evil.example/api/soc','/api/soc/../power-automate','/api/soc?other=1'])assert.equal(allowedRequest(path,'GET',undefined),false);
 assert.equal(allowedRequest('/api/soc','POST','{invalid'),false);
 assert.equal(allowedRequest('/api/soc','DELETE',undefined),false);
});
