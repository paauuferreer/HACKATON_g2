import PostalMime from 'postal-mime';
import {normalizeText,analyze} from './soc.mjs';
export async function enrichMail(mail:any){
 const mime=await PostalMime.parse(mail.bytes,{maxNestingDepth:30,maxHeadersSize:100000});
 let body=normalizeText(mime.text||mime.html||mail.body);const attachments=[];
 for(const attachment of mime.attachments||[]){
  const bytes=typeof attachment.content==='string'?new TextEncoder().encode(attachment.content):new Uint8Array(attachment.content);
  const supported=/^(text\/|application\/(json|xml|csv))/.test(attachment.mimeType||'');
  const extracted=supported&&bytes.length<=100000;
  if(extracted)body+='\n[Adjunto: '+attachment.filename+']\n'+normalizeText(new TextDecoder().decode(bytes));
  attachments.push({name:attachment.filename||'Adjunto',mimeType:attachment.mimeType,size:bytes.length,textExtracted:extracted});
 }
 const truncated=body.length>150000;body=body.slice(0,150000);
 const analysis=analyze(mail.subject,body);
 Object.assign(analysis,{trustedSender:mail.trustedSender,attachments,messageKind:mail.subject.includes('[SOC]')?'Alerta candidata':/directriz|director|petici[oó]n/i.test(mail.subject)?'Directriz candidata':'Por revisar'});
 if(!mail.trustedSender)analysis.warnings.push('Remitente fuera de la lista SOC: conservar y verificar su procedencia.');
 if(attachments.some(a=>!a.textExtracted))analysis.warnings.push('Hay adjuntos binarios o extensos: conservados en el original EML; revisar manualmente.');
 if(truncated)analysis.warnings.push('Texto limitado a 150.000 caracteres; consultar el original completo.');
 return {...mail,body,analysis};
}
