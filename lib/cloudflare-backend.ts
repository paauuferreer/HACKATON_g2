import {env} from 'cloudflare:workers';
import {configureRuntime} from './runtime.mjs';
import {getChatGPTUser} from '@/app/chatgpt-auth';
import {HttpError} from './backend';
configureRuntime(env);
export * from './backend';
export async function guard(request:Request,write=false){
 const user=await getChatGPTUser();if(!user)throw new HttpError(401,'Inicia sesión para acceder.');
 if(write&&request.headers.get('origin')!==new URL(request.url).origin)throw new HttpError(403,'Origen no autorizado.');
 return user;
}
export async function external(request:Request,path:string,actor=''){
 const e=env as unknown as Record<string,string>;if(!e.SOC_BACKEND_URL)return null;
 if(!e.SOC_BACKEND_TOKEN)throw new HttpError(503,'Falta el secreto de conexión PostgreSQL.');
 const target=new URL(e.SOC_BACKEND_URL);if(target.protocol!=='https:'||target.username||target.password||target.search||target.hash)throw new HttpError(503,'El backend requiere una URL HTTPS sin credenciales.');
 const headers:Record<string,string>={'Authorization':`Bearer ${e.SOC_BACKEND_TOKEN}`,'Content-Type':'application/json','X-SOC-Actor':actor};
 const response=await fetch(target.href.replace(/\/$/,'')+path,{method:request.method,headers,...(request.method==='POST'?{body:await request.arrayBuffer()}:{}),signal:AbortSignal.timeout(25000),redirect:'error'});
 const out=new Headers({'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});
 for(const name of ['content-type','content-disposition','x-evidence-sha256']){const value=response.headers.get(name);if(value)out.set(name,value);}
 return new Response(response.body,{status:response.status,headers:out});
}
