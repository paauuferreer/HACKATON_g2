import test from 'node:test';
import assert from 'node:assert/strict';
import {analyze,validIPv4,validAccount,normalizeText,demoMessages} from '../lib/soc.mjs';
test('detecta objetivos explícitos, contradicción y autorización pendiente',()=>{
 const a=analyze('[SOC][P4][CRÍTICO] Uso confirmado de cuenta administrativa', 'SOC-20261103-002-TESTAA. La cuenta privilegiada admin@example.invalid completó una sesión desde 198.51.100.107 y añadió una identidad. | **Direccion relacionada** | 19851100107 | **Criticidad** | Media | No ejecutar una contención sin autorización del responsable.');
 assert.deepEqual(a.accounts,['admin@example.invalid']);assert.deepEqual(a.ips,['198.51.100.107']);assert.equal(a.originalPriority,'P4');assert.equal(a.priority,'Crítica');assert.equal(a.approvalRequired,true);assert.equal(a.warnings.length,3);
});
test('no trata direcciones del pie ni identificadores como objetivos',()=>{
 const a=analyze('[SOC] Aviso','AL-20260101-0001. SOC-20261103-002-ABCDEF. Equipo SOC soc@example.invalid. Dirección relacionada 19851100107.');assert.deepEqual(a.accounts,[]);assert.deepEqual(a.ips,[]);assert.equal(a.priority,'Sin clasificar');
});
test('rechaza IPv4 mal formada o fuera de rango',()=>{for(const x of ['999.1.1.1','19851100107','01.2.3.4','1.2.3','1.2.3.4/24','::1','1.2.3.4extra'])assert.equal(validIPv4(x),false);assert.equal(validIPv4('198.51.100.107'),true);});
test('cuenta: longitud y formato',()=>{assert.equal(validAccount('demo@example.invalid'),true);assert.equal(validAccount('texto con espacios@example.com'),false);assert.equal(validAccount('admin'),false);});
test('varios objetivos obligan a revisar alcance',()=>{const a=analyze('[SOC][ALTA] Cuenta','La cuenta privilegiada uno@example.invalid desde 192.0.2.1. Cuenta relacionada dos@example.invalid desde 192.0.2.2.');assert.equal(a.accounts.length,2);assert.equal(a.ips.length,2);assert.ok(a.warnings.some(x=>x.includes('varios objetivos')));assert.equal(a.approvalRequired,true);});
test('categorías temáticas y prioridades transparentes',()=>{assert.ok(analyze('[SOC][MEDIA] Phishing','Suplantación de correo').topics.includes('Phishing'));assert.equal(analyze('[SOC][BAJA] Vulnerabilidad','Parche pendiente').priority,'Baja');assert.equal(analyze('[SOC][P1] Mensaje','Sin otro indicador').priority,'Sin clasificar');});
test('no renderiza HTML activo como evidencia de texto',()=>{assert.equal(normalizeText('<script>alert(1)</script><b>Alerta</b>&nbsp;SOC'),'Alerta SOC');});
test('demostración usa identidades ficticias y no autoriza acciones',()=>{assert.equal(demoMessages.length,6);for(const m of demoMessages){assert.ok(m.demo);assert.equal(m.analysis.approvalRequired,true);assert.ok(m.sender.endsWith('.invalid'));}});
