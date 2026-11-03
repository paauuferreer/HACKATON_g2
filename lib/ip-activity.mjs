// Read-only analytics. An IP mentioned in an alert is not a containment target.
export const IP_TIME_ZONE='Europe/Madrid';
const hourFormat=new Intl.DateTimeFormat('en-CA',{timeZone:IP_TIME_ZONE,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',hourCycle:'h23'});
const ipv4=value=>/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)&&value.split('.').every(n=>Number(n)<=255&&String(Number(n))===n);
export function canonicalIp(input){
 const value=String(input||'').trim().toLowerCase();
 if(ipv4(value))return value;
 if(!value.includes(':')||/[%\s/\[\]]/.test(value))return null;
 try{
  const host=new URL(`http://[${value}]/`).hostname.slice(1,-1);
  const mapped=host.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
  if(mapped){const a=parseInt(mapped[1],16),b=parseInt(mapped[2],16);return `${a>>8}.${a&255}.${b>>8}.${b&255}`;}
  return host;
 }catch{return null;}
}
export function mentionedIps(row){
 const values=new Set((Array.isArray(row.analysis?.ips)?row.analysis.ips:[]).map(canonicalIp).filter(Boolean));
 const text=`${row.subject||''} ${row.body||''}`;
 const spans=[];
 for(const m of text.matchAll(/(?<![\w:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.]*(?![\w:])/gi)){
  const ip=canonicalIp(m[0]);if(ip){values.add(ip);spans.push([m.index,m.index+m[0].length]);}
 }
 for(const m of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g))if(!spans.some(([a,b])=>m.index>=a&&m.index<b)&&ipv4(m[0]))values.add(m[0]);
 return [...values].sort();
}
function zoned(value){
 if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)||!Number.isFinite(Date.parse(value)))return null;
 const p=Object.fromEntries(hourFormat.formatToParts(new Date(value)).map(x=>[x.type,x.value]));
 return {day:`${p.year}-${p.month}-${p.day}`,hour:Number(p.hour),instant:new Date(value).toISOString()};
}
const dayMs=86400000;
function shift(day,n){return new Date(Date.parse(day+'T12:00:00Z')+n*dayMs).toISOString().slice(0,10);}
function dateInput(value){return /^\d{4}-\d{2}-\d{2}$/.test(value)&&Number.isFinite(Date.parse(value+'T12:00:00Z'))&&new Date(value+'T12:00:00Z').toISOString().slice(0,10)===value;}
export class ActivityInputError extends Error{}
export function ipActivity(rows,params=new URLSearchParams(),now=new Date()){
 const basis=params.get('basis')||'event';if(!['event','received'].includes(basis))throw new ActivityInputError('Selecciona fecha del evento o recepción.');
 const selectedIp=params.get('ip')?canonicalIp(params.get('ip')):null;
 if(params.get('ip')&&!selectedIp)throw new ActivityInputError('Introduce una dirección IPv4 o IPv6 válida.');
 const unique=rows.filter(r=>!r.duplicateOf&&!['No es alerta','Falsa alarma'].includes(r.status));
 const prepared=unique.map(r=>({row:r,ips:mentionedIps(r),time:zoned(basis==='event'?r.analysis?.eventAt:r.receivedAt)}));
 const availableDays=prepared.filter(r=>r.time).map(r=>r.time.day).sort();
 const last=availableDays.at(-1)||zoned(now.toISOString()).day;
 const from=params.get('from')||shift(last,-13),to=params.get('to')||last;
 if(!dateInput(from)||!dateInput(to)||from>to)throw new ActivityInputError('El intervalo de fechas no es válido.');
 if((Date.parse(to)-Date.parse(from))/dayMs>92)throw new ActivityInputError('Selecciona como máximo 93 días.');
 const days=[];for(let day=from;day<=to;day=shift(day,1))days.push(day);
 const ranking=new Map(),cells=new Map();let inRange=0,withoutIp=0,matched=0,mentions=0;
 for(const record of prepared){
  const {time,ips}=record;if(!time||time.day<from||time.day>to)continue;
  inRange++;if(!ips.length){withoutIp++;continue;}
  for(const ip of ips){
   const r=ranking.get(ip)||{ip,count:0,firstAt:time.instant,lastAt:time.instant};r.count++;
   if(time.instant<r.firstAt)r.firstAt=time.instant;if(time.instant>r.lastAt)r.lastAt=time.instant;ranking.set(ip,r);
  }
  if(selectedIp&&!ips.includes(selectedIp))continue;
  matched++;mentions+=selectedIp?1:ips.length;
  const key=`${time.day}|${time.hour}`,cell=cells.get(key)||{day:time.day,hour:time.hour,count:0,ips:new Map()};cell.count++;
  for(const ip of selectedIp?[selectedIp]:ips)cell.ips.set(ip,(cell.ips.get(ip)||0)+1);cells.set(key,cell);
 }
 const ranked=[...ranking.values()].sort((a,b)=>b.count-a.count||a.ip.localeCompare(b.ip));
 const heatmap=[...cells.values()].map(c=>({...c,ips:[...c.ips].map(([ip,count])=>({ip,count})).sort((a,b)=>b.count-a.count||a.ip.localeCompare(b.ip))})).sort((a,b)=>a.day.localeCompare(b.day)||a.hour-b.hour);
 return {timeZone:IP_TIME_ZONE,basis,range:{from,to},available:{from:availableDays[0]||null,to:availableDays.at(-1)||null},selectedIp,
  summary:{alerts:matched,uniqueIps:ranking.size,ipMentions:mentions,inRange,withoutIp,missingDate:prepared.filter(r=>!r.time).length,excluded:rows.length-unique.length},
  days,heatmap,ranking:ranked,maxCell:Math.max(0,...heatmap.map(c=>c.count)),generatedAt:now.toISOString()};
}
