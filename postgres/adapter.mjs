export function postgresSQL(sql){
 const ignore=/^INSERT OR IGNORE\b/i.test(sql);sql=sql.replace(/^INSERT OR IGNORE\b/i,'INSERT');
 let quote=false,index=0,out='';
 for(let i=0;i<sql.length;i++){const c=sql[i];if(c==="'"){out+=c;if(quote&&sql[i+1]==="'"){out+=sql[++i];continue;}quote=!quote;}else out+=c==='?'&&!quote?'$'+(++index):c;}
 return out+(ignore?' ON CONFLICT DO NOTHING':'');
}
export function createDatabase(pool){
 const statement=(sql,values=[])=>({sql,values,bind(...args){return statement(sql,args);},async all(){const r=await pool.query(postgresSQL(sql),values);return {results:r.rows,meta:{changes:r.rowCount}};},async first(){return (await this.all()).results[0]||null;},async run(){return this.all();}});
 return {prepare:statement,async batch(statements){for(let attempt=0;attempt<3;attempt++){
  const client=await pool.connect();try{await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');const results=[];for(const s of statements){const r=await client.query(postgresSQL(s.sql),s.values);results.push({results:r.rows,meta:{changes:r.rowCount}});}await client.query('COMMIT');return results;}catch(e){await client.query('ROLLBACK');if(e.code!=='40001'||attempt===2)throw e;}finally{client.release();}
 }}};
}
