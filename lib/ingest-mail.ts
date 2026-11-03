import {enrichMail} from './mail-content';
import {db,json,failure,HttpError,runtimeEnv} from './backend';
import {validateMail,IngestError} from './ingestion.mjs';

// Shared ingestion endpoint on an OWNER-PRIVATE Site. Sites dispatch authenticates
// OAI-Sites-Authorization before reaching the Worker. Never expose this Site publicly.
// This route only imports evidence; it cannot approve or call the blocking API.
export async function ingestRequest(request:Request){try{
 const e=runtimeEnv();
 if(e.INGEST_MODE!=='power-automate'||!e.BUCKET)throw new HttpError(503,'Recepción no configurada.');
 if(request.headers.get('origin'))throw new HttpError(403,'Usa el flujo de servidor para importar.');
 if(!request.headers.get('content-type')?.includes('application/json'))throw new HttpError(415,'Se requiere JSON.');
 if(Number(request.headers.get('content-length')||0)>3200000)throw new HttpError(413,'Petición demasiado grande.');
 const reader=request.body?.getReader();if(!reader)throw new HttpError(400,'Falta el correo.');
 let size=0;const parts:Uint8Array[]=[];
 while(true){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>3200000){await reader.cancel();throw new HttpError(413,'Petición demasiado grande.');}parts.push(part.value);}
 const buffer=new Uint8Array(size);let offset=0;for(const part of parts){buffer.set(part,offset);offset+=part.length;}
 let input;try{input=JSON.parse(new TextDecoder().decode(buffer));}catch{throw new HttpError(400,'JSON no válido.');}
 const mail=await enrichMail(validateMail(input,{mailbox:e.OUTLOOK_MAILBOX,senders:e.SOC_SENDERS}));
 const previous=await db().prepare('SELECT id FROM incidents WHERE source_key=?').bind(mail.sourceKey).first();
 if(previous)return json({id:previous.id,duplicate:true});
 const id=crypto.randomUUID(),key=`evidence/${id}.eml`,now=new Date().toISOString();
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',mail.bytes))).map(b=>b.toString(16).padStart(2,'0')).join('');
 await e.BUCKET.put(key,mail.bytes,{httpMetadata:{contentType:'message/rfc822'},customMetadata:{sha256:hash}});
 const groupKey=mail.analysis.alertId||mail.analysis.reference||('body:'+Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(mail.body.trim())))).map(b=>b.toString(16).padStart(2,'0')).join(''));
 const stableGroup=mail.body.trim()||mail.analysis.alertId||mail.analysis.reference?groupKey:'message:'+mail.sourceKey;
 const results=await db().batch([
  db().prepare('INSERT OR IGNORE INTO alert_groups (key,incident_id) VALUES (?,?)').bind(stableGroup,id),
  db().prepare('INSERT OR IGNORE INTO incidents (id,source_key,subject,sender,received_at,body,analysis,status,evidence_key,evidence_hash,created_at,group_key,duplicate_of) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,(SELECT CASE WHEN incident_id=? THEN NULL ELSE incident_id END FROM alert_groups WHERE key=?))').bind(id,mail.sourceKey,mail.subject,mail.sender,mail.receivedAt,mail.body,JSON.stringify(mail.analysis),'Nueva',key,hash,now,stableGroup,id,stableGroup),
  db().prepare('INSERT INTO audit (id,actor,event,detail,created_at) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM incidents WHERE id=?)').bind(crypto.randomUUID(),'Power Automate','correo_importado',JSON.stringify({incident:id,sha256:hash,source:'Office 365 Outlook'}),now,id)
 ]);
 if(!results[1].meta.changes){await e.BUCKET.delete(key);const found=await db().prepare('SELECT id FROM incidents WHERE source_key=?').bind(mail.sourceKey).first();return json({id:found?.id,duplicate:true});}
 return json({id,duplicate:false,priority:mail.analysis.priority,topics:mail.analysis.topics,approvalRequired:true},201);
 }catch(error){return error instanceof IngestError?json({error:error.message},error.status):failure(error);}}
