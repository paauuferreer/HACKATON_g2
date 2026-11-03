import {normalizeText, analyze, validAccount} from './soc.mjs';
export class IngestError extends Error {constructor(status,message){super(message);this.status=status;}}
export function validateMail(input, settings) {
 if (!input || typeof input !== 'object' || Array.isArray(input)) throw new IngestError(400,'Se requiere un correo JSON.');
 const mailbox=String(settings.mailbox||'').trim().toLowerCase();
 const senders=String(settings.senders||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
 if (!validAccount(mailbox)||!senders.length) throw new IngestError(503,'Recepción pendiente de configurar.');
 const sender=typeof input.sender==='string'?input.sender.trim().toLowerCase():'';
 if (!validAccount(sender)) throw new IngestError(400,'Remitente no válido.');
 for (const [key,max] of [['messageId',1500],['receivedAt',100]]) {
  if(typeof input[key]!=='string'||!input[key].trim()||input[key].length>max)throw new IngestError(400,`Campo ${key} ausente o demasiado largo.`);
 }
 if(typeof input.subject!=='string'||input.subject.length>2000||typeof input.body!=='string'||input.body.length>300000)throw new IngestError(400,'Asunto o cuerpo no válido.');
 if (!Number.isFinite(Date.parse(input.receivedAt))) throw new IngestError(400,'Fecha de recepción no válida.');
 if (typeof input.emlBase64!=='string'||input.emlBase64.length>2666668||!input.emlBase64.length||input.emlBase64.length%4!==0||!/^[A-Za-z0-9+/]+={0,2}$/.test(input.emlBase64))throw new IngestError(400,'Se requiere el correo original EML en base64 (máximo 2 MB).');
 const binary=atob(input.emlBase64);if(binary.length>2000000)throw new IngestError(413,'Correo original demasiado grande.');
 // Require a MIME/RFC822 header section; never archive an empty export as original evidence.
 if(!/^(?:[\w-]+:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n)+\r?\n/.test(binary))throw new IngestError(400,'La exportación no contiene cabeceras EML válidas.');
 const body=normalizeText(input.body);if(body.length>150000)throw new IngestError(413,'Cuerpo demasiado grande.');
 return {sourceKey:`${mailbox}|${input.messageId}`,sender,subject:input.subject||'(Sin asunto)',receivedAt:new Date(input.receivedAt).toISOString(),body,analysis:analyze(input.subject,body),trustedSender:senders.includes(sender),bytes:Uint8Array.from(binary,c=>c.charCodeAt(0))};
}
