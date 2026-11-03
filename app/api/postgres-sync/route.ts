import {db,json,failure,HttpError,runtimeEnv} from '@/lib/cloudflare-backend';

async function authorize(request:Request){
 const expected=String(runtimeEnv().SOC_SYNC_TOKEN||'');
 const supplied=request.headers.get('X-SOC-Sync-Key')||'';
 if(request.headers.has('origin')||!expected||supplied.length>256)throw new HttpError(403,'Acceso no autorizado.');
 const digest=async(s:string)=>new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
 const [a,b]=await Promise.all([digest(expected),digest(supplied)]);let diff=0;
 for(let i=0;i<a.length;i++)diff|=a[i]^b[i];
 if(diff)throw new HttpError(403,'Acceso no autorizado.');
}
export async function GET(request:Request){
 try{
  await authorize(request);const url=new URL(request.url);const id=url.searchParams.get('id');
  if(id){
   if(!/^[a-f0-9-]{36}$/.test(id))throw new HttpError(400,'ID no válido.');
   const row=await db().prepare('SELECT evidence_key,evidence_hash FROM incidents WHERE id=?').bind(id).first() as any;
   if(!row)throw new HttpError(404,'Correo no encontrado.');
   const object=await runtimeEnv().BUCKET.get(row.evidence_key);
   if(!object)throw new HttpError(404,'Original no disponible.');
   return new Response(object.body,{headers:{'Content-Type':'message/rfc822','Cache-Control':'private, no-store','X-Evidence-SHA256':row.evidence_hash,'X-Content-Type-Options':'nosniff'}});
  }
  const after=url.searchParams.get('after')||'';
  if(after&&!/^[a-f0-9-]{36}$/.test(after))throw new HttpError(400,'Cursor no válido.');
  const result=await db().prepare('SELECT id,subject,sender,received_at,evidence_hash FROM incidents WHERE id>? ORDER BY id LIMIT 50').bind(after).all();
  const rows=result.results as any[];
  return json({rows,next:rows.length===50?rows[rows.length-1].id:null});
 }catch(error){return failure(error);}
}
