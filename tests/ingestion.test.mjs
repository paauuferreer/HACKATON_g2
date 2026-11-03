import test from 'node:test';
import assert from 'node:assert/strict';
import {validateMail} from '../lib/ingestion.mjs';
const settings={mailbox:'equipo@example.invalid',senders:'soc@example.invalid'};
const input={messageId:'<test@example.invalid>',sender:'soc@example.invalid',subject:'[SOC][ALTA] Alerta',receivedAt:'2026-11-03T10:00:00Z',body:'La cuenta privilegiada test@example.invalid desde 192.0.2.10.',emlBase64:btoa('From: soc@example.invalid\r\nSubject: [SOC] Test\r\n\r\nTest')};
test('ingesta conserva evidencia, clave estable y aprobación obligatoria',()=>{const mail=validateMail(input,settings);assert.equal(mail.sourceKey,'equipo@example.invalid|<test@example.invalid>');assert.deepEqual(mail.analysis.ips,['192.0.2.10']);assert.equal(mail.analysis.approvalRequired,true);assert.ok(mail.bytes.length);});
test('no confía en remitentes o configuración ausentes',()=>{for(const s of [{}])assert.throws(()=>validateMail(input,s));});
test('rechaza entrada malformada y exportación ausente',()=>{for(const change of [{receivedAt:'invalid'},{emlBase64:''},{emlBase64:btoa('sin cabeceras')},{messageId:1},{body:'x'.repeat(300001)}])assert.throws(()=>validateMail({...input,...change},settings));});
