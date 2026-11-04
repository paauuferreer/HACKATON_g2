'use client';
import {useEffect,useMemo,useState} from 'react';
import {Activity,ArrowUpRight,Download,RefreshCw,Search,X} from 'lucide-react';
import {socFetch} from '@/lib/soc-client';
import './IpActivity.css';

type Filters={from:string;to:string;ip:string;basis:string};
const initial:Filters={from:'',to:'',ip:'',basis:'event'};
const hours=Array.from({length:24},(_,i)=>i);
const hour=(n:number)=>`${String(n).padStart(2,'0')}:00`;
const dayLabel=(day:string)=>new Intl.DateTimeFormat('es-ES',{timeZone:'Europe/Madrid',weekday:'short',day:'2-digit',month:'short'}).format(new Date(day+'T12:00:00Z'));
const instant=(value:string)=>new Intl.DateTimeFormat('es-ES',{timeZone:'Europe/Madrid',day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}).format(new Date(value));

export function IpActivity({connected,refreshKey,onInvestigate}:any){
 const [filters,setFilters]=useState<Filters>(initial),[draft,setDraft]=useState<Filters>(initial);
 const [data,setData]=useState<any>(null),[error,setError]=useState(''),[loading,setLoading]=useState(false),[reload,setReload]=useState(0);
 const [selectedCell,setSelectedCell]=useState('');
 useEffect(()=>{
  if(!connected)return;let active=true;setLoading(true);
  const params=new URLSearchParams({view:'ip-activity'});for(const [key,value] of Object.entries(filters))if(value)params.set(key,value);
  void(async()=>{try{
   const r=await socFetch('/api/soc?'+params.toString(),{cache:'no-store'});const result:any=await r.json();
   if(!r.ok)throw new Error(result.error||'No se pudo cargar la actividad de IP.');
   if(!active)return;setData(result);setError('');
   if(!filters.from&&!filters.to){const fixed={...filters,...result.range};setFilters(fixed);setDraft(fixed);}
  }catch(e:any){if(active)setError(e.message||'No se pudo actualizar el gráfico.');}finally{if(active)setLoading(false);}})();
  return()=>{active=false;};
 },[filters,connected,refreshKey,reload]);
 const cells=useMemo(()=>new Map<string,any>((data?.heatmap||[]).map((c:any)=>[`${c.day}|${c.hour}`,c])),[data]);
 const chosen=cells.get(selectedCell),peak=data?.heatmap?.find((c:any)=>c.count===data.maxCell);
 function apply(next:Filters){setFilters(next);setDraft(next);setData(null);setSelectedCell('');setError('');}
 function chooseIp(ip:string){apply({...filters,ip});}
 function csv(){
  const values=[['Fecha','Hora','IP','Alertas','Zona_horaria','Fecha_usada'],...data.heatmap.flatMap((cell:any)=>cell.ips.map((ip:any)=>[cell.day,hour(cell.hour),ip.ip,ip.count,data.timeZone,data.basis==='event'?'evento':'recepcion']))];
  const text='\uFEFF'+values.map(row=>row.map((value:any)=>'"'+String(value).replaceAll('"','""')+'"').join(';')).join('\r\n');
  const url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'})),link=document.createElement('a');link.href=url;link.download=`hackapol-ip-${data.range.from}_${data.range.to}.csv`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
 return <div className="ip-activity">
  <section className="panel ip-filters" aria-label="Filtros de actividad de IP">
   <div className="ip-heading"><div><span className="eyebrow">ANÁLISIS TEMPORAL</span><h2>Puntos calientes de IP</h2><p>Localiza qué direcciones concentran alertas y en qué momentos.</p></div><span className="ip-timezone">Europe/Madrid</span></div>
   <form onSubmit={e=>{e.preventDefault();const fields=new FormData(e.currentTarget);apply({from:String(fields.get('from')||''),to:String(fields.get('to')||''),basis:String(fields.get('basis')||'event'),ip:String(fields.get('ip')||'').trim()});}}>
    <label>Desde<input name="from" type="date" required value={draft.from} onInput={e=>{const value=e.currentTarget.value;setDraft(d=>({...d,from:value}));}}/></label>
    <label>Hasta<input name="to" type="date" required min={draft.from||undefined} value={draft.to} onInput={e=>{const value=e.currentTarget.value;setDraft(d=>({...d,to:value}));}}/></label>
    <label>Fecha utilizada<select name="basis" value={draft.basis} onChange={e=>setDraft({...draft,basis:e.target.value})}><option value="event">Momento del evento</option><option value="received">Recepción del correo</option></select></label>
    <label className="ip-search">Dirección IP<input name="ip" type="search" value={draft.ip} maxLength={45} placeholder="Todas las direcciones" list="ip-options" onChange={e=>setDraft({...draft,ip:e.target.value})}/><datalist id="ip-options">{data?.ranking?.map((r:any)=><option key={r.ip} value={r.ip}/>)}</datalist></label>
    <button className="button primary" type="submit" disabled={!connected}><Search size={14}/>Aplicar</button>
   </form>
   <div className="ip-filter-footer"><button className="text-button" onClick={()=>apply(initial)}>Últimos 14 días disponibles</button><span>Máximo 93 días · se consulta todo el histórico guardado</span></div>
  </section>
  {!connected&&<section className="panel empty"><Activity size={34}/><h3>Conecta tu sesión privada</h3><p>El gráfico utiliza los correos de tu espacio. Pulsa «Conectar sesión privada» arriba.</p></section>}
  {error&&<div role="alert" className="notice error"><span>{error} {data?'Se conserva la última lectura correcta.':''}</span><button className="button secondary" onClick={()=>setReload(n=>n+1)}>Reintentar</button></div>}
  {connected&&!data&&loading&&<div className="ip-loading" role="status"><RefreshCw size={20} className="spin"/>Calculando actividad de IP…</div>}
  {connected&&data&&<>
   <div className="ip-summary">
    <div className="panel"><span>Alertas mostradas</span><strong>{data.summary.alerts}</strong><small>Únicas, con IP válida</small></div>
    <div className="panel"><span>IP distintas en el período</span><strong>{data.summary.uniqueIps}</strong><small>Antes de filtrar una dirección</small></div>
    <div className="panel"><span>Pico de actividad</span><strong>{data.maxCell}<small> alertas / hora</small></strong><small>{peak?`${dayLabel(peak.day)} · ${hour(peak.hour)}`:'Sin actividad en el intervalo'}</small></div>
   </div>
   <section className="panel ip-chart" aria-labelledby="ip-chart-title">
    <div className="ip-chart-head"><div><h2 id="ip-chart-title">Actividad por día y hora</h2><p>{data.selectedIp?<><code>{data.selectedIp}</code><button aria-label="Quitar filtro de IP" className="ip-clear" onClick={()=>chooseIp('')}><X size={13}/></button></>:'Todas las IP del período'} · {data.basis==='event'?'fecha del evento':'fecha de recepción'}</p></div><button className="button secondary" onClick={csv} disabled={!data.heatmap.length}><Download size={14}/>CSV</button></div>
    <div className="ip-legend"><span>Alertas únicas por hora</span><div><span>Menos</span>{[0,1,2,3,4].map(n=><i key={n} className={`ip-level-${n}`}/>)}<span>Más · máximo {data.maxCell}</span></div></div>
    <div className="ip-grid-scroll"><table className="ip-grid"><caption className="ip-sr">Número de alertas con IP por fecha y hora de Madrid. Selecciona una celda para ver sus direcciones.</caption><thead><tr><th scope="col">DÍA / HORA</th>{hours.map(h=><th key={h} scope="col">{String(h).padStart(2,'0')}</th>)}</tr></thead><tbody>{data.days.map((day:string)=><tr key={day}><th scope="row">{dayLabel(day)}<small>{day}</small></th>{hours.map(h=>{const key=`${day}|${h}`,cell=cells.get(key),count=cell?.count||0,level=count?Math.max(1,Math.ceil(count/data.maxCell*4)):0;return <td key={h}><button type="button" disabled={!count} aria-label={`${day}, ${hour(h)}: ${count} alertas`} aria-pressed={selectedCell===key} title={`${day} · ${hour(h)}–${hour(h+1)} · ${count} alertas`} className={`ip-cell ip-level-${level} ${selectedCell===key?'ip-selected':''}`} onClick={()=>setSelectedCell(key)}>{count||<span aria-hidden="true">·</span>}</button></td>;})}</tr>)}</tbody></table></div>
    {!data.heatmap.length&&<div className="ip-no-results"><Activity size={24}/><div><strong>No hay actividad de IP para estos filtros.</strong><p>Amplía las fechas, quita la IP o prueba con la fecha de recepción.</p></div></div>}
    <div className="ip-chart-foot"><span>Selecciona una celda con actividad para ver las IP.</span><span aria-live="polite">{loading?'Actualizando…':`Lectura: ${instant(data.generatedAt)}`}</span></div>
   </section>
   <div className="ip-detail-grid">
    <section className="panel ip-ranking"><div className="ip-section-title"><h2>IP con más alertas</h2><span>Top 15 del período</span></div>{data.ranking.length?data.ranking.slice(0,15).map((r:any,index:number)=><button className={`ip-rank ${data.selectedIp===r.ip?'chosen':''}`} key={r.ip} onClick={()=>chooseIp(r.ip)} aria-label={`Filtrar ${r.ip}: ${r.count} alertas`}><span className="ip-rank-number">{String(index+1).padStart(2,'0')}</span><span className="ip-rank-body"><span><code>{r.ip}</code><b>{r.count}</b></span><i><em style={{width:`${r.count/data.ranking[0].count*100}%`}}/></i></span><ArrowUpRight size={15}/></button>):<p className="muted">No se han encontrado direcciones válidas.</p>}</section>
    <section className="panel ip-detail"><div className="ip-section-title"><h2>{chosen?'Detalle de la franja':'Explora una franja'}</h2><Activity size={18}/></div>{chosen?<><p className="ip-slot">{dayLabel(chosen.day)}<strong>{hour(chosen.hour)}–{hour(chosen.hour+1)}</strong><span>{chosen.count} alertas únicas · {chosen.ips.length} IP</span></p><div className="ip-detail-ips">{chosen.ips.map((r:any)=><div key={r.ip}><button className="text-button" onClick={()=>chooseIp(r.ip)}>{r.ip}</button><span>{r.count} alertas</span><button className="text-button" aria-label={`Buscar alertas de ${r.ip}`} onClick={()=>onInvestigate(r.ip)}><Search size={13}/>Investigar</button></div>)}</div></>:<p className="muted">Pulsa una celda del mapa para ver qué direcciones coinciden en esa hora. Puedes filtrar una IP o abrir sus alertas en la bandeja.</p>}<div className="ip-explainer"><strong>Cómo se cuentan los datos</strong><p>Una alerta cuenta una vez en el mapa y una vez por cada IP que menciona en el ranking. La intensidad representa volumen, no confirma que una dirección sea maliciosa.</p><p>Se excluyen duplicados, falsas alarmas y mensajes marcados como «No es alerta». Las fechas no se mezclan: {data.summary.missingDate} alertas del histórico no tienen {data.basis==='event'?'fecha de evento válida':'fecha de recepción válida'}. En este intervalo, {data.summary.withoutIp} alertas no contienen IP válida.</p><p>IPv4 e IPv6 · no se reconstruyen direcciones malformadas. En el cambio de horario, una hora repetida se agrupa en la misma celda.</p></div></section>
   </div>
  </>}
 </div>;
}
