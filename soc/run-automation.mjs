import pg from 'pg';
import {pathToFileURL} from 'node:url';
import {runtimeSettings} from './automation-policy.mjs';
import {runCycle} from './automation-engine.mjs';
import {postgresStore} from './automation-store.mjs';
import {blockingApi} from './automation-api.mjs';

export async function main(env=process.env,args=process.argv.slice(2)){
 const settings=runtimeSettings(env),dryRun=args.includes('--dry-run')||!settings.enabled;
 if(!dryRun&&(settings.policy!=='sql'&&!Number.isFinite(settings.startAt)||!env.BLOCK_API_KEY&&!env.API_TOKEN))throw new Error('Configuración de activación incompleta');
 const client=new pg.Client({host:env.PGHOST,port:Number(env.PGPORT||5432),user:env.PGUSER,password:env.PGPASSWORD,database:env.PGDATABASE,
  ssl:{rejectUnauthorized:true},connectionTimeoutMillis:10000,statement_timeout:15000,options:`-c timezone=UTC${dryRun?' -c default_transaction_read_only=on':''}`,application_name:'hackapol-automation-v1'});
 try{
  const api=blockingApi(dryRun?'':env.BLOCK_API_KEY||env.API_TOKEN);
  if(!dryRun)await api.check();
  await client.connect();
  const result=await runCycle({store:postgresStore(client,settings),api,settings,dryRun});
  console.log(JSON.stringify(result));
  if(!result.ready||result.unknown)process.exitCode=2;
  return result;
 }finally{await client.end().catch(()=>{});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{await main();}catch(error){console.error(JSON.stringify({error:'Automatización detenida; no repetir operaciones sin comprobar.',code:['BLOCK_API_AUTH_FAILED','BLOCK_API_UNAVAILABLE'].includes(error.safeCode)?error.safeCode:/^[A-Z0-9]{5}$/.test(error.code||'')?error.code:'AUTOMATION_STOPPED'}));process.exitCode=1;}
}
