import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compiledServer = path.resolve(__dirname, 'dist', 'server.js');

// Em produção (após npm run build), executa o bundle JavaScript nativo de alta performance
if (fs.existsSync(compiledServer)) {
  await import('./dist/server.js');
} else {
  // Em desenvolvimento (tsx server.ts)
  await import('./server/app.ts');
}

