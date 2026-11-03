export const PAGES_ORIGIN = 'https://paauuferreer.github.io';
export const SITE_ORIGIN = 'https://hackapol-soc-equipo-dos.sampol-1496.chatgpt.site';
export function allowedRequest(path: unknown, method: unknown, body: unknown): boolean {
  if (typeof path !== 'string' || !['GET','POST'].includes(String(method))) return false;
  let url:URL;try{url = new URL(path, SITE_ORIGIN);}catch{return false;}
  if (!path.startsWith('/api/soc') || url.origin !== SITE_ORIGIN || url.pathname !== '/api/soc' || url.hash) return false;
  if (method === 'GET') return !body && [...url.searchParams.keys()].every(k => ['view','id','q','offset'].includes(k));
  if (url.search || typeof body !== 'string' || body.length > 6000) return false;
  try { return ['review','reconcile','bloquear','liberar'].includes(JSON.parse(body).action); } catch { return false; }
}
