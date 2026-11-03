'use client';
import {useEffect,useRef,useState} from 'react';
import {PAGES_ORIGIN,allowedRequest} from '@/lib/pages-protocol';
export default function PagesBridge(){
 const [active,setActive]=useState(false),[error,setError]=useState(''),[email,setEmail]=useState('');
 const activeRef=useRef(false),seen=useRef(new Set<string>());
 const channelRef=useRef('');
 useEffect(()=>{channelRef.current=new URLSearchParams(location.search).get('channel')||'';},[]);
 useEffect(()=>{
  const listener=async(event:MessageEvent)=>{
   const m=event.data;
   if(!activeRef.current||event.origin!==PAGES_ORIGIN||event.source!==window.opener||m?.channel!==channelRef.current||m?.kind!=='soc-request')return;
   if(typeof m.id!=='string'||m.id.length>100||seen.current.has(m.id))return;
   const send=(value:any,transfer:Transferable[]=[])=>window.opener?.postMessage({kind:'soc-response',channel:channelRef.current,id:m.id,...value},PAGES_ORIGIN,transfer);
   if(!allowedRequest(m.path,m.method,m.body)){send({error:'Operación no autorizada para este panel.'});return;}
   if(seen.current.size>=20000){send({error:'Reconecta la sesión privada.'});return;}
   seen.current.add(m.id);
   try{
    const r=await fetch(m.path,{method:m.method,cache:'no-store',...(m.method==='POST'?{headers:{'Content-Type':'application/json'},body:m.body}:{})});
    const buffer=await r.arrayBuffer();
    if(buffer.byteLength>4*1024*1024){send({error:'Respuesta demasiado grande. Reduce la búsqueda.'});return;}
    const headers:Record<string,string>={};for(const name of ['content-type','content-disposition','x-evidence-sha256']){const value=r.headers.get(name);if(value)headers[name]=value;}
    send({status:r.status,headers,buffer},[buffer]);
   }catch{send({error:'Conexión interrumpida. Comprueba el historial antes de repetir una operación.'});}
  };
  window.addEventListener('message',listener);return()=>window.removeEventListener('message',listener);
 },[]);
 async function connect(){
  setError('');
  if(!window.opener||!/^[-a-z0-9]{36}$/i.test(channelRef.current)){setError('Abre esta conexión desde el panel de GitHub Pages.');return;}
  try{const r=await fetch('/api/soc?offset=0',{cache:'no-store'});const data:any=await r.json();if(!r.ok||!data.user?.email)throw Error('Inicia sesión con la cuenta autorizada.');
   setEmail(data.user.email);activeRef.current=true;setActive(true);
   window.opener.postMessage({kind:'soc-ready',channel:channelRef.current},PAGES_ORIGIN);
  }catch(e:any){setError(e.message);}
 }
 function disconnect(){activeRef.current=false;setActive(false);window.opener?.postMessage({kind:'soc-disconnected',channel:channelRef.current},PAGES_ORIGIN);}
 return <main style={{maxWidth:520,margin:'60px auto',padding:30}}><div className="eyebrow">HACKAPOL · SESIÓN PRIVADA</div><h1>{active?'Panel conectado':'Conectar GitHub Pages'}</h1><p style={{lineHeight:1.8}}>{active?`Sesión de ${email}. Mantén esta ventana abierta mientras utilizas el panel. Puedes volver a la pestaña de GitHub Pages.`:'Permite al panel de tu repositorio consultar los correos y gestionar las operaciones que autorices con tu sesión.'}</p><p className="muted">Panel autorizado: https://paauuferreer.github.io/HACKATON_g2/</p><p>Las claves permanecen en el servidor. Cada bloqueo sigue requiriendo revisión y confirmación.</p>{error&&<p className="form-error">{error}</p>}{active?<button className="button secondary" onClick={disconnect}>Desconectar panel</button>:<button className="button primary" onClick={()=>void connect()}>Conectar mi panel de GitHub</button>}<p><a className="text-button" target="_top" href={'/signin-with-chatgpt?return_to='+encodeURIComponent('/pages-bridge'+(typeof location!=='undefined'?location.search:''))}>Iniciar sesión privada</a></p></main>;
}
