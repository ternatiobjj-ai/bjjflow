import { Request, Response, NextFunction } from 'express';
import { getBackendSupabaseClient } from '../services/supabaseBackend';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    isMasterAdmin: boolean;
  };
}

/**
 * Middleware para validar se o usuário é administrador para rotas protegidas
 */
export async function requireAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  const userEmail = req.headers['x-user-email'] as string;

  if (!authHeader && !userEmail) {
    res.status(401).json({ error: 'Não autorizado. Identificação de usuário ausente.' });
    return;
  }

  try {
    const client = getBackendSupabaseClient();
    const queryEmail = userEmail ? userEmail.toLowerCase().trim() : '';
    
    if (queryEmail) {
      const { data: user, error } = await client
        .from('usuarios')
        .select('id, email, role, is_master_admin, status')
        .ilike('email', queryEmail)
        .maybeSingle();

      if (error || !user) {
        res.status(401).json({ error: 'Usuário não encontrado no sistema.' });
        return;
      }

      if (user.status !== 'aprovado' && user.status !== 'ativo') {
        res.status(403).json({ error: 'Acesso negado. Usuário não possui status aprovado.' });
        return;
      }

      if (user.role !== 'admin' && !user.is_master_admin) {
        res.status(403).json({ error: 'Acesso negado. Esta operação exige privilégios de Administrador.' });
        return;
      }

      req.user = {
        id: user.id,
        email: user.email,
        role: user.role,
        isMasterAdmin: Boolean(user.is_master_admin)
      };
      next();
      return;
    }

    next();
  } catch (err: any) {
    res.status(500).json({ error: 'Erro interno ao validar autorização.', details: err?.message });
  }
}
