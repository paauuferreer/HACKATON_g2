let configured;
export function configureRuntime(value){configured=value;}
export function runtimeEnv(){if(!configured)throw new Error('Runtime no configurado');return configured;}
