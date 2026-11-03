import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs/promises';
import {timingSafeEqual,createHash} from 'node:crypto';
import pg from 'pg';
import {createDatabase} from './adapter.mjs';
import {configureRuntime} from '../lib/runtime.mjs';
import {ingestRequest} from '../lib/ingest-mail';
import {readSoc,writeSoc} from '../lib/soc-service';
import {failure,HttpError} from '../lib/backend';
if(!process.env.DATABASE_URL||!process.env.SOC_BACKEND_TOKEN||process.env.SOC_BACKEND_TOKEN.length<32)throw Error('Configura DATABASE_URL y SOC_BACKEND_TOKEN (mínimo 32 caracteres).');
if(!process.env.APPROVER_EMAILS||!process.env.OUTLOOK_MAILBOX||!process.env.SOC_SENDERS)throw Error('Configura buzón, remitentes de confianza y responsables.');
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,max:10,options:'-c search_path=hackapol_soc',statement_timeout:15000});
const root=path.resolve(process.env.EVIDENCE_DIR||'./data/evidence');await fs.mkdir(root,{recursive:true});
function evidencePath(key:string){if(!/^evidence\/[a-f0-9-]{36}\.eml$/.test(key))throw Error('Clave de evidencia inválida');return path.join(root,path.basename(key));}
const bucket={async put(key:string,bytes:Uint8Array){await fs.writeFile(evidencePath(key),bytes,{flag:'wx',mode:0o600});},async get(key:string){try{return {body:await fs.readFile(evidencePath(key))};}catch(e:any){if(e.code==='ENOENT')return null;throw e;}},async head(key:string){try{return await fs.stat(evidencePath(key));}catch(e:any){if(e.code==='ENOENT')return null;throw e;}},async delete(key:string){await fs.unlink(evidencePath(key));}};
configureRuntime({...process.env,INGEST_MODE:'power-automate',DB:createDatabase(pool),BUCKET:bucket});
const digest=(s:string)=>createHash('sha256').update(s).digest();
const server=http.createServer(async(req,res)=>{try{
 const token=String(req.headers.authorization||'').replace(/^Bearer /,'');if(!timingSafeEqual(digest(token),digest(process.env.SOC_BACKEND_TOKEN!)))throw new HttpError(401,'Acceso no autorizado.');
 const url=new URL(req.url||'/','http://internal');if(!['/ingest','/soc'].includes(url.pathname))throw new HttpError(404,'Ruta no encontrada.');
 if(!['GET','POST'].includes(req.method||''))throw new HttpError(405,'Método no permitido.');
 if(url.pathname==='/ingest'&&req.method!=='POST')throw new HttpError(405,'Se requiere POST.');
 const max=url.pathname==='/ingest'?3200000:6000;let length=0;const chunks=[];for await(const chunk of req){length+=chunk.length;if(length>max)throw new HttpError(413,'Petición demasiado grande.');chunks.push(chunk);}
 const request=new Request(url,{method:req.method,headers:{'Content-Type':String(req.headers['content-type']||'')},...(req.method==='POST'?{body:Buffer.concat(chunks)}:{})});
 const actor=String(req.headers['x-soc-actor']||'').toLowerCase();
 const readers=String(process.env.READER_EMAILS||process.env.APPROVER_EMAILS).toLowerCase().split(',').map(s=>s.trim());
 if(url.pathname==='/soc'&&!readers.includes(actor))throw new HttpError(403,'Usuario no autorizado.');
 const response=url.pathname==='/ingest'?await ingestRequest(request):req.method==='GET'?await readSoc(request,actor):await writeSoc(request,actor);
 res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
 }catch(e){const response=failure(e);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(await response.text());}});
server.listen(Number(process.env.PORT||8080),process.env.HOST||'127.0.0.1',()=>console.log('Backend SOC PostgreSQL listo. Publicar detrás de HTTPS; no exponer PostgreSQL al navegador.'));
process.on('SIGTERM',()=>server.close(()=>{void pool.end();}));
