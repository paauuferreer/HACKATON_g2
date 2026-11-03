import pg from 'pg';
import {createHandler} from './service.mjs';
const env=process.env;
const pool=new pg.Pool({host:env.PGHOST,port:Number(env.PGPORT||5432),user:env.PGUSER,password:env.PGPASSWORD,database:env.PGDATABASE,
 ssl:{rejectUnauthorized:true},max:3,idleTimeoutMillis:10000,connectionTimeoutMillis:8000,statement_timeout:10000,
 options:'-c default_transaction_read_only=on -c timezone=UTC',application_name:'hackapol-web-postgres'});
// Avoid logging query data or connection secrets on idle client errors.
pool.on('error',()=>{});
export const soc=createHandler({pool,env});
export const health=createHandler({pool,env,health:true});
