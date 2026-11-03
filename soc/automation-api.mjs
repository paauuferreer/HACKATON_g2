const BASE='https://hackathon-api-a6ckg4g2ejg4cda4.francecentral-01.azurewebsites.net/equipo-2';
// Destination is fixed: an email, database row or env var cannot redirect the API key.
export function blockingApi(key,fetcher=fetch){
 async function request(path,method='GET',body){
  if(!key)throw new Error('Falta BLOCK_API_KEY');
  const r=await fetcher(`${BASE}/${path}`,{method,headers:{'X-API-Key':key,'Content-Type':'application/json'},
   ...(body?{body:JSON.stringify(body)}:{}),redirect:'error',signal:AbortSignal.timeout(15000)});
  const text=await r.text();if(text.length>1000000)throw new Error('Respuesta demasiado grande');
  return {status:r.status,data:JSON.parse(text)};
 }
 return {
  async check(){
   const r=await request('bloqueos?tipo=usuario&limit=1&offset=0');
   if([401,403].includes(r.status))throw Object.assign(new Error('La API rechaza la credencial del equipo 2.'),{safeCode:'BLOCK_API_AUTH_FAILED'});
   if(r.status!==200||!Array.isArray(r.data)||r.data.some(x=>x.equipo_id!==2||x.tipo!=='usuario'))throw Object.assign(new Error('No se pudo validar la API del equipo 2.'),{safeCode:'BLOCK_API_UNAVAILABLE'});
   return true;
  },
  async find(user){
   for(let offset=0;offset<10000;offset+=100){
    const r=await request(`bloqueos?tipo=usuario&limit=100&offset=${offset}`);
    if(r.status!==200||!Array.isArray(r.data)||r.data.length>100)throw new Error('Comprobación no disponible');
    if(r.data.some(x=>x.equipo_id!==2||x.tipo!=='usuario'||typeof x.valor!=='string'||typeof x.activo!=='boolean'||!Number.isSafeInteger(x.id)))throw new Error('Estado inesperado');
    const found=r.data.filter(x=>x.valor.toLowerCase()===user);
    if(found.length>1)throw new Error('Estado ambiguo');
    if(found.length&&found[0].valor!==user)throw new Error('Identidad con normalización ambigua');
    if(found.length)return found[0];
    if(r.data.length<100)return null;
   }
   throw new Error('Comprobación incompleta');
  },
  block(user){return request('bloquear','POST',{usuario:user});}
 };
}
