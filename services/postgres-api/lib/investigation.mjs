import {readFile} from 'node:fs/promises';

export function costSnapshot(data){
 if(typeof data.generado!=='string'||!Array.isArray(data.coste)||data.coste.length!==3)throw new Error('Informe no disponible');
 const keys=['horas_parada','parada','respuesta','restauracion','externos','comunicacion','total','evitado_auto06'];
 const scenarios=data.coste.map(row=>{
  if(typeof row.escenario!=='string'||keys.some(k=>!Number.isFinite(row[k])||row[k]<0))throw new Error('Informe inválido');
  return Object.fromEntries(['escenario',...keys].map(k=>[k,row[k]]));
 });
 // Never send victims, originals or other unrelated report contents with costs.
 return {generatedAt:data.generado,timeZone:'Europe/Madrid',source:'docs/informe/web.json',estimated:true,scenarios};
}
export async function readCosts(){
 return costSnapshot(JSON.parse(await readFile(new URL('../report/web.json',import.meta.url),'utf8')));
}
export async function readChain(client,url){
 const offsetText=url.searchParams.get('offset')||'0';
 if(!/^\d{1,6}$/.test(offsetText))throw new Error('Paginación inválida');
 const offset=Number(offsetText);
 await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const rows=(await client.query('SELECT * FROM public.v_cadena_victimas ORDER BY orden_victima,victima LIMIT $1 OFFSET $2',[51,offset])).rows;
  const victims=rows.slice(0,50);
  // Timestamp WITHOUT time zone from the contract is local Madrid, never UTC.
  const phases=(await client.query('SELECT r.*,r.evento_local::text AS evento_local,r.aviso_local::text AS aviso_local FROM public.v_cadena_ransomware r WHERE victima = ANY($1::text[]) ORDER BY orden_victima,evento_local,orden_fase,alerta_id',[victims.map(v=>v.victima)])).rows;
  const predictions=(await client.query('SELECT p.*,p.siguiente_victima_estimada_evento::text AS siguiente_victima_estimada_evento,p.siguiente_victima_estimada_aviso::text AS siguiente_victima_estimada_aviso FROM public.v_cadena_prediccion p')).rows;
  await client.query('COMMIT');
  return {source:'PostgreSQL · v_cadena_*',timeZone:'Europe/Madrid',queriedAt:new Date().toISOString(),offset,hasMore:rows.length>50,
   victims:victims.map(v=>({...v,phases:phases.filter(p=>p.victima===v.victima)})),prediction:predictions[0]||null};
 }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}
}
