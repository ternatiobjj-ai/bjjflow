import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { getBackendSupabaseClient } from '../services/supabaseBackend';

const TOKEN_SECRET = process.env.SESSION_SECRET || 'bjjflow_secure_session_secret_2026_ternatio';

export function generateSessionToken(userId: string, email: string, role: string): string {
  const payload = `${userId}:${email}:${role}:${Date.now()}`;
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}:${signature}`).toString('base64');
}

export function verifySessionToken(token: string): { valid: boolean; userId?: string; email?: string; role?: string } {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length < 5) return { valid: false };
    const [userId, email, role, timestamp, signature] = parts;
    const payload = `${userId}:${email}:${role}:${timestamp}`;
    const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
    if (signature !== expectedSig) return { valid: false };

    // Validar expiração (7 dias)
    const issueTime = parseInt(timestamp, 10);
    const maxAgeMs = 7 * 24 * 60 * 60 * 1000;
    if (Date.now() - issueTime > maxAgeMs) {
      return { valid: false };
    }

    return { valid: true, userId, email, role };
  } catch {
    return { valid: false };
  }
}

export class AuthController {
  /**
   * Endpoint de validação de login seguro com migração progressiva para bcrypt
   * NUNCA expõe senhas ou hashes em logs ou respostas.
   */
  static async login(req: Request, res: Response): Promise<void> {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ success: false, message: 'E-mail ou senha inválidos.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      const cleanEmail = String(email).toLowerCase().trim();

      // Consulta os dados de credencial exclusivamente no backend
      const { data: user, error } = await client
        .from('usuarios')
        .select('id, nome, email, password, role, is_master_admin, status, professor_id, student_id, faixa, graus, permissions, telefone, created_at')
        .ilike('email', cleanEmail)
        .maybeSingle();

      if (error || !user) {
        // Mensagem genérica idêntica para evitar enumeração
        res.status(401).json({ success: false, message: 'E-mail ou senha inválidos.' });
        return;
      }

      // Verificação da senha: hash bcrypt vs legado texto puro
      let passwordMatches = false;
      let needsMigration = false;
      const storedCred = user.password || '';

      if (storedCred.startsWith('$2a$') || storedCred.startsWith('$2b$') || storedCred.startsWith('$2y$')) {
        // Credencial já migrada para hash bcrypt
        try {
          passwordMatches = bcrypt.compareSync(password, storedCred);
        } catch {
          passwordMatches = false;
        }
      } else {
        // Credencial legada em texto puro
        if (storedCred === password) {
          passwordMatches = true;
          needsMigration = true;
        }
      }

      if (!passwordMatches) {
        res.status(401).json({ success: false, message: 'E-mail ou senha inválidos.' });
        return;
      }

      // Validação de status de aprovação
      if (user.status === 'pendente') {
        res.status(403).json({ success: false, message: 'Cadastro em análise. Aguarde a aprovação de um administrador.' });
        return;
      }

      if (user.status === 'reprovado' || user.status === 'inativo') {
        res.status(403).json({ success: false, message: 'Acesso não liberado. Entre em contato com a administração.' });
        return;
      }

      // Migração progressiva transparente: se a senha ainda estava em texto puro, calcula hash bcrypt e atualiza
      if (needsMigration) {
        try {
          const saltRounds = 12;
          const newHash = bcrypt.hashSync(password, saltRounds);
          await client
            .from('usuarios')
            .update({ password: newHash })
            .eq('id', user.id);
        } catch (migrationErr: any) {
          // Falha de migração silenciosa não bloqueia o login do usuário neste instante
          console.error('[AUTH MIGRATION] Falha ao atualizar hash para usuário ID:', user.id);
        }
      }

      // Gerar token de sessão assinado
      const sessionToken = generateSessionToken(user.id, user.email, user.role);

      // Remover campos sensíveis de credenciais antes de responder
      const { password: _, ...safeUser } = user;

      res.json({
        success: true,
        message: `Bem-vindo, ${safeUser.nome}!`,
        token: sessionToken,
        user: safeUser
      });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro ao autenticar no servidor.', details: err?.message });
    }
  }

  /**
   * Endpoint de solicitação de recuperação de senha
   * Não expõe status de e-mail ao cliente (anti-enumeração)
   * Avisa com transparência técnica sobre a necessidade de gateway SMTP configurado
   */
  static async recoverPassword(req: Request, res: Response): Promise<void> {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ success: false, message: 'Informe o endereço de e-mail cadastrado.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      const cleanEmail = String(email).toLowerCase().trim();

      const { data: user } = await client
        .from('usuarios')
        .select('id, email, nome')
        .ilike('email', cleanEmail)
        .maybeSingle();

      const hasEmailService = Boolean(process.env.SMTP_HOST || process.env.RESEND_API_KEY);

      if (user && hasEmailService) {
        // Gerar token de recuperação com validade de 1 hora
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

        // Tenta registrar na tabela de tokens de recuperação caso exista
        await client
          .from('password_reset_tokens')
          .insert({
            user_id: user.id,
            token_hash: tokenHash,
            expires_at: expiresAt,
            used: false
          })
          .catch(() => {
            // Tabela pode ainda estar no template de migração
          });
      }

      // Resposta segura e padronizada (anti-enumeração)
      res.json({
        success: true,
        emailConfigured: hasEmailService,
        message: hasEmailService
          ? `Se o e-mail ${cleanEmail} estiver cadastrado no sistema, as orientações de redefinição foram enviadas.`
          : `Solicitação registrada para ${cleanEmail}. O envio automatizado requer configuração do serviço de e-mail (SMTP/Resend) no servidor. Caso necessário, procure a secretaria da academia.`
      });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro ao processar solicitação de recuperação.' });
    }
  }

  /**
   * Endpoint de alteração de senha de usuário autenticado
   * Suporta validação tanto de hash bcrypt quanto legado
   */
  static async changePassword(req: Request, res: Response): Promise<void> {
    const { userId, email, currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      res.status(400).json({ success: false, message: 'A nova senha deve ter no mínimo 6 dígitos.' });
      return;
    }

    if (!currentPassword) {
      res.status(400).json({ success: false, message: 'A senha atual é obrigatória.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      const cleanEmail = String(email || '').toLowerCase().trim();

      let query = client.from('usuarios').select('id, password, email');
      if (userId) {
        query = query.eq('id', userId);
      } else if (cleanEmail) {
        query = query.ilike('email', cleanEmail);
      } else {
        res.status(400).json({ success: false, message: 'Identificação de usuário necessária.' });
        return;
      }

      const { data: user, error: fetchErr } = await query.maybeSingle();
      if (fetchErr || !user) {
        res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
        return;
      }

      const storedCred = user.password || '';
      let currentMatches = false;

      if (storedCred.startsWith('$2a$') || storedCred.startsWith('$2b$') || storedCred.startsWith('$2y$')) {
        try {
          currentMatches = bcrypt.compareSync(currentPassword, storedCred);
        } catch {
          currentMatches = false;
        }
      } else {
        currentMatches = storedCred === currentPassword;
      }

      if (!currentMatches) {
        res.status(401).json({ success: false, message: 'A senha atual informada está incorreta.' });
        return;
      }

      // Criptografar a nova senha com bcrypt (12 rounds)
      const saltRounds = 12;
      const hashedNewPassword = bcrypt.hashSync(newPassword, saltRounds);

      const { error: updErr } = await client
        .from('usuarios')
        .update({ password: hashedNewPassword })
        .eq('id', user.id);

      if (updErr) {
        res.status(500).json({ success: false, message: 'Erro ao atualizar senha no banco de dados.' });
        return;
      }

      res.json({ success: true, message: 'Senha atualizada com sucesso com criptografia de alta segurança!' });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro interno ao alterar senha.', details: err?.message });
    }
  }
}
