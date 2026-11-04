import test from 'node:test';import assert from 'node:assert/strict';
import {ipActivity,mentionedIps,canonicalIp} from '../lib/ip-activity.mjs';
const row=(id,date,body='IP de origen: 198.51.100.5',extra={})=>({id,subject:'Alerta SOC',body,receivedAt:date,analysis:{eventAt:date,ips:[]},status:'Nueva',...extra});
const query=s=>new URLSearchParams(s);
test('Madrid: medianoche, exclusiones y una sola cuenta por alerta aunque repita IP',()=>{
 const rows=[row('1','2026-11-02T23:30:00Z','198.51.100.5 repite 198.51.100.5'),row('2','2026-11-02T23:30:00Z','198.51.100.5',{duplicateOf:'1'}),row('3','2026-11-02T23:30:00Z','198.51.100.5',{status:'Falsa alarma'})];
 const s=ipActivity(rows,query('from=2026-11-03&to=2026-11-03'));assert.equal(s.summary.alerts,1);assert.equal(s.summary.excluded,2);assert.equal(s.ranking[0].count,1);assert.equal(s.heatmap[0].hour,0);assert.equal(s.heatmap[0].day,'2026-11-03');
});
test('fecha del evento no se mezcla con recepción cuando falta',()=>{
 const r=row('1','2026-11-03T10:00:00Z','198.51.100.5',{analysis:{eventAt:null}});
 assert.equal(ipActivity([r]).summary.missingDate,1);assert.equal(ipActivity([r]).summary.alerts,0);assert.equal(ipActivity([r],query('basis=received')).summary.alerts,1);
});
test('IPv6 canónica y mapeada; rechaza IP inválida y no inventa puntos',()=>{
 assert.equal(canonicalIp('2001:0DB8:0:0:0:0:0:1'),'2001:db8::1');assert.equal(canonicalIp('::ffff:192.0.2.1'),'192.0.2.1');
 assert.deepEqual(mentionedIps(row('1','2026-11-03T10:00:00Z','2001:db8::1 y ::ffff:192.0.2.1; 19851100107; 999.1.1.1')),['192.0.2.1','2001:db8::1']);
});
test('una alerta con varias IP cuenta una vez en el mapa y una vez por IP en ranking',()=>{
 const rows=[row('1','2026-11-03T10:00:00Z','198.51.100.5 192.0.2.1'),row('2','2026-11-03T11:00:00Z','192.0.2.1')];
 const all=ipActivity(rows);assert.equal(all.summary.alerts,2);assert.equal(all.summary.ipMentions,3);assert.equal(all.ranking[0].count,2);
 const one=ipActivity(rows,query('ip=198.51.100.5'));assert.equal(one.summary.alerts,1);assert.equal(one.heatmap.length,1);assert.equal(one.heatmap[0].ips.length,1);
});
test('horario de verano: hora repetida se agrupa en hora local; primavera no inventa actividad',()=>{
 const fall=ipActivity([row('1','2026-10-25T00:30:00Z'),row('2','2026-10-25T01:30:00Z')]);assert.equal(fall.heatmap[0].hour,2);assert.equal(fall.heatmap[0].count,2);
 const spring=ipActivity([row('1','2026-03-29T01:30:00Z')]);assert.equal(spring.heatmap[0].hour,3);
});
test('rango inclusivo y validación de filtros',()=>{
 const rows=[row('1','2026-11-03T10:00:00Z')];
 assert.equal(ipActivity(rows,query('from=2026-11-01&to=2026-11-03')).days.length,3);
 for(const q of ['from=2026-02-30','from=2026-11-04&to=2026-11-01','from=2026-01-01&to=2026-11-01','ip=19851100107','basis=other'])assert.throws(()=>ipActivity(rows,query(q)));
});
test('histórico completo más allá de 200 filas y ausencia de datos',()=>{
 assert.equal(ipActivity(Array.from({length:250},(_,i)=>row(String(i),'2026-11-03T10:00:00Z'))).summary.alerts,250);
 const empty=ipActivity([],query('from=2026-11-03&to=2026-11-03'));assert.equal(empty.maxCell,0);assert.equal(empty.ranking.length,0);assert.equal(empty.days.length,1);
});
