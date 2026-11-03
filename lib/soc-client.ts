'use client';
import { SITE_ORIGIN, allowedRequest } from './pages-protocol';
declare global { interface Window { __SOC_PAGES__?: boolean; } }
let bridge: Window | null = null;
let channel = '';
let ready = false;
const pending = new Map<string, {resolve:(response:Response)=>void; reject:(error:Error)=>void; timer:ReturnType<typeof setTimeout>}>();
export const isPages = () => typeof window !== 'undefined' && window.__SOC_PAGES__ === true;
export const sessionReady = () => !isPages() || (ready && !!bridge && !bridge.closed);
function notify(){window.dispatchEvent(new Event('soc-connection'));}
function disconnect(){ready=false;for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error('Sesión desconectada. Comprueba el registro antes de repetir una operación.'));}pending.clear();notify();}
if(typeof window!=='undefined') window.addEventListener('message',event=>{
  if(event.origin!==SITE_ORIGIN || event.source!==bridge || event.data?.channel!==channel)return;
  const message=event.data;
  if(message.kind==='soc-ready'){ready=true;notify();return;}
  if(message.kind==='soc-disconnected'){disconnect();return;}
  if(message.kind!=='soc-response')return;
  const request=pending.get(message.id);if(!request)return;
  clearTimeout(request.timer);pending.delete(message.id);
  if(message.error){request.reject(new Error(message.error));return;}
  request.resolve(new Response(message.buffer,{status:message.status,headers:message.headers}));
});
export function connectSession(){
  if(bridge&&!bridge.closed){bridge.focus();return;}
  disconnect();channel=crypto.randomUUID();
  bridge=window.open(`${SITE_ORIGIN}/pages-bridge?channel=${encodeURIComponent(channel)}`,'hackapol-private-session','popup,width=620,height=680');
  if(!bridge)throw new Error('Permite la ventana emergente para conectar tu sesión privada.');
}
export async function socFetch(path:string,init:RequestInit={}):Promise<Response>{
  if(!isPages())return fetch(path,init);
  if(!sessionReady()){if(ready)disconnect();throw new Error('Conecta tu sesión privada para consultar el buzón.');}
  const method=init.method||'GET',body=init.body||undefined;
  if(!allowedRequest(path,method,body))throw new Error('Esta operación solo está disponible en el servidor privado.');
  const id=crypto.randomUUID();
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error('Sin respuesta del servidor. Comprueba el historial antes de repetir una operación.'));},method==='POST'?180000:30000);
    pending.set(id,{resolve,reject,timer});
    bridge!.postMessage({kind:'soc-request',channel,id,path,method,body},SITE_ORIGIN);
  });
}
export async function downloadEvidence(id:string){
  const response=await socFetch('/api/soc?view=evidence&id='+encodeURIComponent(id));
  if(!response.ok)throw new Error('No se pudo descargar la evidencia.');
  const url=URL.createObjectURL(await response.blob());const a=document.createElement('a');
  a.href=url;a.download=`incidente-${id}.eml`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
