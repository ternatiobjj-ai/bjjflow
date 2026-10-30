import { Router, Request, Response } from 'express';
import { checkDatabaseHealth, BACKEND_SUPABASE_URL } from '../services/supabaseBackend';

const router = Router();

// Endpoint de verificação de integridade (Health Check)
router.get('/health', async (_req: Request, res: Response) => {
  const dbHealth = await checkDatabaseHealth();
  res.json({
    status: dbHealth.ok ? 'healthy' : 'degraded',
    service: 'Ternatio BJJ Backend API',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    database: dbHealth
  });
});

// Endpoint de status das configurações
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    supabaseConfigured: Boolean(BACKEND_SUPABASE_URL),
    supabaseUrl: BACKEND_SUPABASE_URL,
    apiVersion: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

export default router;
