import {guard,external,json,failure,runtimeEnv,HttpError} from '@/lib/cloudflare-backend';
import {readSoc,writeSoc,canApprove} from '@/lib/soc-service';
export const dynamic='force-dynamic';
export async function GET(request:Request){try{const user=await guard(request);const view=new URL(request.url).searchParams.get('view');if(view==='chain'||view==='costs'){const response=await external(request,'/soc'+new URL(request.url).search,user.email,true);if(!response)throw new HttpError(503,'Backend de investigación pendiente de configurar.');return response;}return await external(request,'/soc'+new URL(request.url).search,user.email)||await readSoc(request,user.email);}catch(e){return failure(e);}}
export async function POST(request:Request){try{
 const user=await guard(request,true);
 // Connection setup remains in Sites, never forwarded to the PostgreSQL service.
 if(Number(request.headers.get('content-length')||0)>6000)throw new HttpError(413,'Petición demasiado grande.');
 const raw=await request.clone().text();if(raw.length>6000)throw new HttpError(413,'Petición demasiado grande.');
 let input;try{input=JSON.parse(raw);}catch{throw new HttpError(400,'JSON no válido.');}
 if(input.action==='connectionSecret'){
  if(!canApprove(user.email))throw new HttpError(403,'Se requiere responsable.');
  const token=runtimeEnv().POWER_AUTOMATE_SERVICE_TOKEN;if(!token)throw new HttpError(409,'Credencial no configurada.');
  return json({header:'OAI-Sites-Authorization',value:`Bearer ${token}`});
 }
 return await external(request,'/soc',user.email)||await writeSoc(request,user.email);
 }catch(e){return failure(e);}}
