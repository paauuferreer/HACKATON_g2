import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {costSnapshot} from '../lib/investigation.mjs';
// Run from the repository checkout before packaging the Vercel service.
const source=new URL('../../../docs/informe/web.json',import.meta.url);
const data=JSON.parse(await readFile(source,'utf8'));
costSnapshot(data); // Fail the build rather than ship an absent/invalid report.
const directory=new URL('../report/',import.meta.url);
await mkdir(directory,{recursive:true});
await writeFile(new URL('web.json',directory),JSON.stringify({generado:data.generado,coste:data.coste}));
console.log('Informe económico validado y preparado (sin datos personales).');
