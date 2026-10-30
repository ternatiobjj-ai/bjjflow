import { Request, Response } from 'express';
import { getBackendSupabaseClient } from '../services/supabaseBackend';

export class AuthController {
  /**
   * Endpoint de validação de login seguro
   */
  static async login(req: Request, res: Response): Promise<void> {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ success: false, message: 'E-mail e senha são obrigatórios.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      const cleanEmail = String(email).toLowerCase().trim();

      const { data: user, error } = await client
        .from('usuarios')
        .select('id, nome, email, password, role, is_master_admin, status, professor_id, student_id, faixa, graus, permissions')
        .ilike('email', cleanEmail)
        .maybeSingle();

      if (error || !user) {
        res.status(401).json({ success: false, message: 'E-mail ou senha inválidos.' });
        return;
      }

      if (user.password !== password) {
        res.status(401).json({ success: false, message: 'E-mail ou senha inválidos.' });
        return;
      }

      if (user.status === 'pendente') {
        res.status(403).json({ success: false, message: 'Cadastro em análise. Aguarde a aprovação de um administrador.' });
        return;
      }

      if (user.status === 'reprovado' || user.status === 'inativo') {
        res.status(403).json({ success: false, message: 'Acesso não liberado. Entre em contato com a administração.' });
        return;
      }

      // Remover senha da resposta retornada
      const { password: _, ...safeUser } = user;
      res.json({
        success: true,
        message: `Bem-vindo, ${safeUser.nome}!`,
        user: safeUser
      });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro ao autenticar no servidor.', details: err?.message });
    }
  }

  /**
   * Endpoint de solicitação de recuperação de senha
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

      // Resposta genérica segura para evitar enumeração de contas
      res.json({
        success: true,
        userFound: Boolean(user),
        message: `Se o e-mail ${cleanEmail} estiver cadastrado no sistema, as instruções e orientações para redefinição de senha foram encaminhadas.`
      });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro ao processar solicitação de recuperação.' });
    }
  }

  /**
   * Endpoint de alteração de senha de usuário autenticado
   */
  static async changePassword(req: Request, res: Response): Promise<void> {
    const { userId, email, currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      res.status(400).json({ success: false, message: 'A nova senha deve ter no mínimo 6 dígitos.' });
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

      if (user.password && user.password !== currentPassword) {
        res.status(401).json({ success: false, message: 'A senha atual informada está incorreta.' });
        return;
      }

      const { error: updErr } = await client
        .from('usuarios')
        .update({ password: newPassword })
        .eq('id', user.id);

      if (updErr) {
        res.status(500).json({ success: false, message: 'Erro ao atualizar senha no banco de dados.' });
        return;
      }

      res.json({ success: true, message: 'Senha atualizada com sucesso!' });
    } catch (err: any) {
      res.status(500).json({ success: false, message: 'Erro interno ao alterar senha.', details: err?.message });
    }
  }
}
