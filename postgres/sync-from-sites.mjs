import pg from 'pg';
import PostalMime from 'postal-mime';
import {createHash} from 'node:crypto';

// Only INSERT into the existing immutable inbox. Its existing trigger owns classification.
const required=['PGHOST','PGPORT','PGDATABASE','PGUSER','PGPASSWORD','SOC_SOURCE_URL','SOC_SOURCE_BEARER','SOC_SYNC_TOKEN'];
for(const key of required)if(!process.env[key])throw new Error(`Falta ${key}`);
const source=new URL(process.env.SOC_SOURCE_URL);
if(source.protocol!=='https:'||source.username||source.password)throw new Error('Origen HTTPS requerido');
const client=new pg.Client({host:process.env.PGHOST,port:Number(process.env.PGPORT),database:process.env.PGDATABASE,user:process.env.PGUSER,password:process.env.PGPASSWORD,ssl:{rejectUnauthorized:true},connectionTimeoutMillis:15000,statement_timeout:30000,application_name:'hackapol-github-sync'});
const stats={read:0,inserted:0,existing:0,failed:0};
async function readSource(params){
 const url=new URL('/api/postgres-sync',source);url.search=new URLSearchParams(params).toString();
 const response=await fetch(url,{headers:{'OAI-Sites-Authorization':`Bearer ${process.env.SOC_SOURCE_BEARER}`,'X-SOC-Sync-Key':process.env.SOC_SYNC_TOKEN},redirect:'error',signal:AbortSignal.timeout(30000)});
 if(!response.ok)throw new Error(`Origen HTTP ${response.status}`);
 return response;
}
try{
 await client.connect();await client.query("SET timezone='UTC'");
 const lock=await client.query('SELECT pg_try_advisory_lock(724102,2) AS locked');
 if(!lock.rows[0].locked)throw new Error('Otra sincronización está en curso');
 let after='';
 do{
  const page=await (await readSource(after?{after}:{})).json();
  if(!Array.isArray(page.rows)||page.rows.length>50)throw new Error('Página no válida');
  for(const row of page.rows){
   stats.read++;
   try{
    if((await client.query('SELECT 1 FROM public.bandeja_entrada WHERE correo_id=$1',[row.id])).rowCount){stats.existing++;continue;}
    const response=await readSource({id:row.id});const bytes=Buffer.from(await response.arrayBuffer());
    if(bytes.length>2000000||createHash('sha256').update(bytes).digest('hex')!==row.evidence_hash)throw new Error('Integridad EML no válida');
    const mail=await PostalMime.parse(bytes);
    const originalId=mail.messageId||`sites:${row.id}`;
    const messageId=originalId.length<=255?originalId:`sites:${row.id}`;
    const utf8=bytes.toString('utf8');const lossless=Buffer.from(utf8).equals(bytes)&&!utf8.includes('\0');
    const headers={mime:mail.headers,source:'hackapol-sites',source_id:row.id,original_message_id:originalId,original_subject:row.subject,eml_sha256:row.evidence_hash,eml_encoding:lossless?'utf8':'base64'};
    const attachments=(mail.attachments||[]).map(a=>({filename:a.filename,mimeType:a.mimeType,contentId:a.contentId}));
    const body=mail.html||mail.text||'';
    const result=await client.query(`INSERT INTO public.bandeja_entrada
     (correo_id,id_mensaje_correo,remitente_correo,destinatarios,asunto_correo,cuerpo_correo_raw,cabeceras,adjuntos,eml_raw,fecha_hora_correo,canal)
     VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10,'POWER_AUTOMATE') ON CONFLICT DO NOTHING RETURNING correo_id`,
     [row.id,messageId,row.sender,JSON.stringify({to:mail.to,cc:mail.cc}),Array.from(row.subject).slice(0,500).join(''),body,JSON.stringify(headers),JSON.stringify(attachments),lossless?utf8:bytes.toString('base64'),row.received_at]);
    if(result.rowCount)stats.inserted++;else stats.existing++;
   }catch(error){stats.failed++;console.error(JSON.stringify({error:'Correo pendiente de reintento',code:/^[A-Z0-9]{5}$/.test(error.code||'')?error.code:'SYNC_RECORD_FAILED'}));}
  }
  if(page.next&&page.next<=after)throw new Error('Cursor sin avance');after=page.next||'';
 }while(after);
 console.log(JSON.stringify(stats));
 const counts=await client.query('SELECT (SELECT count(*) FROM public.bandeja_entrada) AS correos,(SELECT count(*) FROM public.alertas) AS alertas,(SELECT count(*) FROM public.correos_malformados) AS para_revision');
 console.log(JSON.stringify({database:counts.rows[0]}));
 if(stats.failed)process.exitCode=1;
}catch(error){console.error(JSON.stringify({error:'Sincronización incompleta',code:/^[A-Z0-9]{5}$/.test(error.code||'')?error.code:'SYNC_FAILED'}));process.exitCode=1;}
finally{await client.end().catch(()=>{});}
