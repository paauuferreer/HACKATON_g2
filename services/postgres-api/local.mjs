import http from 'node:http';
import {soc,health} from './lib/runtime.mjs';
http.createServer((req,res)=>{
 const pathname=new URL(req.url,'http://localhost').pathname;
 if(['/soc','/api/soc'].includes(pathname))return soc(req,res);
 if(['/health','/api/health'].includes(pathname))return health(req,res);
 res.writeHead(404);res.end();
}).listen(Number(process.env.PORT||8090),'127.0.0.1',()=>console.log('API de validación en localhost:8090'));
