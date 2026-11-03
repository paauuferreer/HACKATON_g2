import {external,failure} from '@/lib/cloudflare-backend';
import {ingestRequest} from '@/lib/ingest-mail';
export const dynamic='force-dynamic';
export async function POST(request:Request){try{return await external(request,'/ingest')||await ingestRequest(request);}catch(e){return failure(e);}}
