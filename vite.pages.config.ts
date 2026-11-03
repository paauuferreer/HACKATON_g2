import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import {fileURLToPath} from 'node:url';
export default defineConfig({root:'github-pages',base:'/HACKATON_g2/',plugins:[react()],resolve:{alias:{'@':fileURLToPath(new URL('.',import.meta.url))}},publicDir:'../public',build:{outDir:'../dist-pages',emptyOutDir:true}});
