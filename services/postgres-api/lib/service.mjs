import {readChain,readCosts} from './investigation.mjs';
import {createHash,timingSafeEqual} from 'node:crypto';

export class HttpError extends Error {constructor(status,message){super(message);this.status=status;}}
const digest=s=>createHash('sha256').update(s).digest();
const emails=s=>String(s||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
export function authenticate(headers,env){
 const secret=env.SOC_BACKEND_TOKEN;
 if(!secret||secret.length<32)throw new HttpError(503,'Backend pendiente de configurar.');
 const authorization=String(headers.authorization||'');
 if(authorization.length>1024||!timingSafeEqual(digest(authorization),digest(`Bearer ${secret}`)))throw new HttpError(401,'Acceso no autorizado.');
 if(headers.origin)throw new HttpError(403,'Esta API solo admite llamadas del servidor.');
 const actor=String(headers['x-soc-actor']||'').trim().toLowerCase();
 if(!emails(env.READER_EMAILS||env.APPROVER_EMAILS).includes(actor))throw new HttpError(403,'Usuario no autorizado.');
 return actor;
}

const priority={P1:'Crítica',P2:'Alta',P3:'Media',P4:'Baja'};
const states={NUEVA:'Nueva',EN_REVISION:'En revisión',CONFIRMADA:'Confirmada',FALSA_ALARMA:'Falsa alarma',NO_SOC:'No es alerta',CERRADA:'Cerrada'};
const iso=value=>value?new Date(value).toISOString():null;
export function toIncident(row){
 return {id:row.alerta_id,subject:row.asunto_correo,sender:row.remitente_correo,receivedAt:iso(row.fecha_hora_correo),
  body:'El original íntegro se conserva en PostgreSQL. La vista de evidencias está pendiente de incorporar al contrato.',
  status:states[row.estado]||row.estado,duplicateOf:null,revision:null,evidenceHash:null,
  analysis:{priority:priority[row.soc_prioridad]||'Sin clasificar',sourcePriority:row.soc_prioridad,topics:[row.clase_incibe||'Sin clasificar'],
   incibeClass:row.clase_incibe||'Sin clasificar',incibeType:row.tipo_incibe,incibeReason:row.justificacion_categoria,
   classificationReviewed:!!row.revisado_por_humano,reference:row.referencia_soc||row.id_alerta_soc,
   source:row.fuente_herramienta,assets:row.equipo_afectado?[row.equipo_afectado]:[],
   accounts:row.usuario_implicado?[row.usuario_implicado]:[],relatedUsers:row.usuario_implicado?[row.usuario_implicado]:[],
   ips:row.ip_afectada?[row.ip_afectada]:[],eventAt:iso(row.fecha_hora_evento),severitySource:row.soc_peligrosidad,
   warnings:[...(row.inconsistencias||[]),...(row.motivo_sospecha?[row.motivo_sospecha]:[])],attachments:[]}};
}
const group=(rows,label,count='total')=>rows.map(r=>({label:String(r[label]??'Sin identificar'),count:Number(r[count])}));
export const dashboardViews=['v_alertas','v_kpis','v_stats_clase','v_stats_fuente','v_stats_prioridad_peligrosidad','v_stats_estado','v_top_equipos','v_top_usuarios','v_timeline','v_incibe_taxonomia'];
export async function checkReadiness(client){
 const rows=(await client.query("SELECT table_name FROM information_schema.views WHERE table_schema='public'")).rows;
 const present=new Set(rows.map(r=>r.table_name));const missingViews=dashboardViews.filter(name=>!present.has(name));
 return {database:'PostgreSQL',dashboardReady:!missingViews.length,productionReady:false,missingViews,
  pending:['Contrato de evidencias y correos no SOC','Vistas de auditoría y operaciones','Escrituras auditadas con control de concurrencia','Registro durable y reconciliación de bloqueos','Migración validada del histórico de revisiones y operaciones de Sites']};
}
export async function readDashboard(client,url,actor,env){
 const requested=url.searchParams.get('view');
 if(requested==='chain')return readChain(client,url);
 if(requested==='costs')return readCosts();
 if(requested)throw new HttpError(503,'Esta vista requiere ampliar el contrato de PostgreSQL. La web de producción continúa en Sites.');
 const offsetText=url.searchParams.get('offset')||'0';
 if(!/^\d{1,6}$/.test(offsetText))throw new HttpError(400,'Paginación no válida.');
 const offset=Number(offsetText),q=(url.searchParams.get('q')||'').slice(0,200);
 const pattern='%'+q.replace(/[\\%_]/g,'\\$&')+'%';
 const filter="concat_ws(' ',asunto_correo,remitente_correo,titulo,usuario_implicado,equipo_afectado,ip_afectada::text,referencia_soc) ILIKE $1 ESCAPE E'\\\\'";
 await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const incidents=(await client.query(`SELECT * FROM public.v_alertas WHERE ${filter} ORDER BY fecha_hora_correo DESC,alerta_id LIMIT 200 OFFSET $2`,[pattern,offset])).rows;
  const total=Number((await client.query(`SELECT count(*) AS total FROM public.v_alertas WHERE ${filter}`,[pattern])).rows[0].total);
  const k=(await client.query('SELECT * FROM public.v_kpis')).rows[0];
  const classes=(await client.query('SELECT clase,total FROM public.v_stats_clase ORDER BY total DESC,clase')).rows;
  const sources=(await client.query('SELECT fuente,sum(total)::bigint AS total FROM public.v_stats_fuente GROUP BY fuente ORDER BY total DESC,fuente')).rows;
  const priorities=(await client.query('SELECT soc_prioridad,sum(total)::bigint AS total FROM public.v_stats_prioridad_peligrosidad GROUP BY soc_prioridad ORDER BY soc_prioridad')).rows;
  const assets=(await client.query('SELECT equipo,total FROM public.v_top_equipos ORDER BY total DESC,equipo LIMIT 10')).rows;
  const users=(await client.query('SELECT usuario,total FROM public.v_top_usuarios ORDER BY total DESC,usuario LIMIT 10')).rows;
  const days=(await client.query("SELECT to_char(hora AT TIME ZONE 'UTC','YYYY-MM-DD') AS dia,sum(total)::bigint AS total FROM public.v_timeline GROUP BY 1 ORDER BY 1")).rows;
  const statesRows=(await client.query('SELECT estado,total FROM public.v_stats_estado')).rows;
  await client.query('COMMIT');
  return {config:{database:'PostgreSQL de Azure',storageReady:true,ingestMode:'power-automate',outlookReady:true,mailbox:env.OUTLOOK_MAILBOX,team:2,blockingReady:false,approversReady:false},
   user:{email:actor,canApprove:false},capabilities:{dashboard:true,review:false,evidence:false,history:false,blocking:false,productionReady:false},
   notice:'Backend en validación: lectura de alertas únicas desde PostgreSQL. Aún no sustituye el panel de producción.',
   incidents:incidents.map(toIncident),total,offset,hasMore:offset+incidents.length<total,operations:[],audit:[],
   stats:{received:Number(k.correos_recibidos),uniqueAlerts:Number(k.alertas_unicas)-Number(k.falsas_alarmas)-Number(k.no_soc),
    duplicates:Number(k.duplicadas),needsReview:Number(k.pendientes),excluded:Number(k.falsas_alarmas)+Number(k.no_soc),
    closed:Number(statesRows.find(r=>r.estado==='CERRADA')?.total||0),malformed:Number(k.malformados),
    classes:group(classes,'clase'),sources:group(sources,'fuente'),priorities:priorities.map(r=>({label:priority[r.soc_prioridad]||r.soc_prioridad,count:Number(r.total)})),
    assets:group(assets,'equipo'),users:group(users,'usuario'),days:group(days,'dia')}};
 }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}

export function createHandler({pool,env,health=false}){
 return async function handler(req,res){
  let client;res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Type','application/json; charset=utf-8');
  try{
   const actor=authenticate(req.headers,env);
   if(req.method!=='GET'){res.setHeader('Allow','GET');throw new HttpError(405,'Esta fase solo permite lectura; no se ejecutó ninguna operación.');}
   const url=new URL(req.url,'https://backend.invalid');client=await pool.connect();
   const result=health?await checkReadiness(client):await readDashboard(client,url,actor,env);
   res.statusCode=200;res.end(JSON.stringify(result));
  }catch(error){res.statusCode=error instanceof HttpError?error.status:503;res.end(JSON.stringify({error:error instanceof HttpError?error.message:'PostgreSQL no está disponible. No se han usado datos alternativos.'}));}
  finally{client?.release();}
 };
}
