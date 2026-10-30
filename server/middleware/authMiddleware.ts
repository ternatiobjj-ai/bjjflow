import { Request, Response, NextFunction } from 'express';
import { getBackendSupabaseClient } from '../services/supabaseBackend';
import { verifySessionToken } from '../controllers/authController';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    isMasterAdmin: boolean;
    studentId?: string;
    professorId?: string;
  };
}

/**
 * Middleware base para autenticar requisições via Bearer Token ou cabeçalho de e-mail autenticado
 */
export async function authenticateToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  const userEmail = req.headers['x-user-email'] as string;

  let verifiedEmail = '';
  let verifiedUserId = '';

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const tokenResult = verifySessionToken(token);
    if (tokenResult.valid && tokenResult.email) {
      verifiedEmail = tokenResult.email;
      verifiedUserId = tokenResult.userId || '';
    }
  }

  if (!verifiedEmail && userEmail) {
    verifiedEmail = userEmail.toLowerCase().trim();
  }

  if (!verifiedEmail) {
    res.status(401).json({ error: 'Não autorizado. Sessão inválida ou expirada.' });
    return;
  }

  try {
    const client = getBackendSupabaseClient();
    let query = client
      .from('usuarios')
      .select('id, email, role, is_master_admin, status, student_id, professor_id');

    if (verifiedUserId) {
      query = query.eq('id', verifiedUserId);
    } else {
      query = query.ilike('email', verifiedEmail);
    }

    const { data: user, error } = await query.maybeSingle();

    if (error || !user) {
      res.status(401).json({ error: 'Usuário não localizado no sistema.' });
      return;
    }

    if (user.status !== 'aprovado' && user.status !== 'ativo') {
      res.status(403).json({ error: 'Acesso bloqueado. Usuário sem aprovação ativa.' });
      return;
    }

    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      isMasterAdmin: Boolean(user.is_master_admin || user.role === 'admin'),
      studentId: user.student_id,
      professorId: user.professor_id
    };

    next();
  } catch (err: any) {
    res.status(500).json({ error: 'Erro interno ao validar sessão no servidor.' });
  }
}

/**
 * Middleware para exigir perfil Administrador no servidor
 */
export async function requireAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  await authenticateToken(req, res, () => {
    if (!req.user || (req.user.role !== 'admin' && !req.user.isMasterAdmin)) {
      res.status(403).json({ error: 'Acesso negado. Esta operação exige privilégios de Administrador.' });
      return;
    }
    next();
  });
}

/**
 * Middleware para exigir perfil Professor ou Administrador
 */
export async function requireInstructorOrAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  await authenticateToken(req, res, () => {
    if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'professor' && !req.user.isMasterAdmin)) {
      res.status(403).json({ error: 'Acesso negado. Esta operação exige privilégios de Professor ou Administrador.' });
      return;
    }
    next();
  });
}

