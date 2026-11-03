import {db,json,HttpError,config,runtimeEnv,performAction,reconcile} from './backend';
import {incibeClasses,incidentStates,statistics} from './taxonomy.mjs';
import {analyze} from './soc.mjs';
import {ipActivity,ActivityInputError} from './ip-activity.mjs';
export function rowToIncident(r:any){let analysis=JSON.parse(r.analysis);if(!analysis.incibeClass)analysis={...analysis,...analyze(r.subject,r.body||''),previousRuleVersion:analysis.ruleVersion};return {id:r.id,subject:r.subject,sender:r.sender,receivedAt:r.received_at,body:r.body,analysis,status:r.status==='Pendiente'?'Nueva':r.status,evidenceHash:r.evidence_hash,duplicateOf:r.duplicate_of,revision:r.revision||0,updatedAt:r.updated_at};}
export function canApprove(actor:string){return String(runtimeEnv().APPROVER_EMAILS||'').toLowerCase().split(',').map(s=>s.trim()).includes(actor.toLowerCase());}
export async function readSoc(request:Request,actor:string){
 const url=new URL(request.url),view=url.searchParams.get('view');
 if(view==='ip-activity'){
  const rows=await db().prepare('SELECT id,subject,body,analysis,status,received_at,duplicate_of FROM incidents').all();
  try{return json(ipActivity(rows.results.map(rowToIncident),url.searchParams));}
  catch(error){if(error instanceof ActivityInputError)throw new HttpError(400,error.message);throw error;}
 }
 if(view==='evidence'){
  const row=await db().prepare('SELECT evidence_key,evidence_hash FROM incidents WHERE id=?').bind(url.searchParams.get('id')||'').first() as any;
  if(!row)throw new HttpError(404,'Evidencia no encontrada.');const object=await runtimeEnv().BUCKET.get(row.evidence_key);if(!object)throw new HttpError(404,'Original no disponible.');
  return new Response(object.body,{headers:{'Content-Type':'message/rfc822','Content-Disposition':'attachment; filename="evidencia-soc.eml"','Cache-Control':'private, no-store','X-Evidence-SHA256':row.evidence_hash,'X-Content-Type-Options':'nosniff'}});
 }
 if(view==='history'){const id=url.searchParams.get('id')||'';const logs=await db().prepare('SELECT * FROM audit WHERE detail LIKE ? ORDER BY created_at DESC').bind('%'+id.replace(/[%_]/g,'')+'%').all();return json({audit:logs.results});}
 const q=(url.searchParams.get('q')||'').slice(0,200);const offset=Math.max(0,Math.min(1000000,parseInt(url.searchParams.get('offset')||'0')||0));
 const where='LOWER(subject || body || sender || analysis) LIKE ?';const pattern='%'+q.toLowerCase()+'%';
 const [rows,count,meta,ops,logs]=await Promise.all([
  db().prepare(`SELECT * FROM incidents WHERE ${where} ORDER BY received_at DESC,id LIMIT 200 OFFSET ?`).bind(pattern,offset).all(),
  db().prepare(`SELECT COUNT(*) AS total FROM incidents WHERE ${where}`).bind(pattern).first() as Promise<any>,
  db().prepare('SELECT id,subject,body,analysis,status,received_at,duplicate_of FROM incidents').all(),
  db().prepare('SELECT * FROM operations ORDER BY created_at DESC LIMIT 250').all(),
  db().prepare('SELECT * FROM audit ORDER BY created_at DESC LIMIT 250').all()
 ]);
 return json({config:{...config(),database:runtimeEnv().DATABASE_URL?'PostgreSQL':'Almacenamiento provisional Sites'},user:{email:actor,canApprove:canApprove(actor)},incidents:rows.results.map(rowToIncident),total:Number(count?.total||0),offset,hasMore:offset+rows.results.length<Number(count?.total||0),stats:statistics(meta.results.map(rowToIncident)),operations:ops.results,audit:logs.results});
}
export async function reviewIncident(actor:string,input:any){
 if(!canApprove(actor))throw new HttpError(403,'Se requiere responsable autorizado.');
 if(!incibeClasses.includes(input.incibeClass)||!incidentStates.includes(input.status)||!['Crítica','Alta','Media','Baja','Sin clasificar'].includes(input.priority)||typeof input.reason!=='string'||input.reason.trim().length<12||input.reason.length>2000||!Number.isInteger(input.revision))throw new HttpError(400,'Revisa clase, prioridad, estado, versión y justificación.');
 const row=await db().prepare('SELECT * FROM incidents WHERE id=?').bind(input.incidentId).first() as any;if(!row)throw new HttpError(404,'Alerta no encontrada.');
 if(row.revision!==input.revision)throw new HttpError(409,'Otra persona ha modificado la alerta. Actualiza antes de guardar.');
 const previous=JSON.parse(row.analysis),next={...previous,incibeClass:input.incibeClass,priority:input.priority,incibeReason:input.reason.trim(),classificationReviewed:true,reviewedBy:actor,reviewedAt:new Date().toISOString()};
 const duplicateOf=typeof input.duplicateOf==='string'&&input.duplicateOf.trim()?input.duplicateOf.trim():null;
 if(duplicateOf){const root=await db().prepare('SELECT id,duplicate_of FROM incidents WHERE id=?').bind(duplicateOf).first();if(!root||root.duplicate_of||root.id===row.id)throw new HttpError(400,'El duplicado debe apuntar a una alerta original distinta.');
  if(await db().prepare('SELECT id FROM incidents WHERE duplicate_of=? LIMIT 1').bind(row.id).first())throw new HttpError(409,'Esta alerta tiene duplicados vinculados. No se puede convertir en hija.');}
 const now=new Date().toISOString();
 const result=await db().batch([
  db().prepare('INSERT INTO audit (id,actor,event,detail,created_at) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM incidents WHERE id=? AND revision=?)').bind(crypto.randomUUID(),actor,'alerta_revisada',JSON.stringify({incident:row.id,before:{class:previous.incibeClass,priority:previous.priority,status:row.status,duplicateOf:row.duplicate_of},after:{class:next.incibeClass,priority:next.priority,status:input.status,duplicateOf},reason:input.reason}),now,row.id,input.revision),
  db().prepare('UPDATE incidents SET analysis=?,status=?,duplicate_of=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?').bind(JSON.stringify(next),input.status,duplicateOf,now,row.id,input.revision)
 ]);
 if(!result[1].meta.changes)throw new HttpError(409,'La alerta cambió durante la edición. Actualiza.');return {updated:true};
}
export async function writeSoc(request:Request,actor:string){
 if(!request.headers.get('content-type')?.includes('application/json'))throw new HttpError(415,'Se requiere JSON.');
 const raw=await request.text();if(raw.length>6000)throw new HttpError(413,'Petición demasiado grande.');let input;try{input=JSON.parse(raw);}catch{throw new HttpError(400,'JSON no válido.');}
 if(input.action==='review')return json(await reviewIncident(actor,input));
 if(input.action==='reconcile'&&typeof input.operationId==='string')return json(await reconcile(actor,input.operationId));
 return json(await performAction(actor,input));
}
