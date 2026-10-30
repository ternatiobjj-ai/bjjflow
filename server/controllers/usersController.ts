import { Request, Response } from 'express';
import { getBackendSupabaseClient } from '../services/supabaseBackend';

export class UsersController {
  /**
   * Listar usuários com filtros de status
   */
  static async listUsers(req: Request, res: Response): Promise<void> {
    try {
      const client = getBackendSupabaseClient();
      const status = req.query.status as string;

      let query = client
        .from('usuarios')
        .select('id, nome, email, role, is_master_admin, status, professor_id, student_id, faixa, graus, permissions, telefone, created_at')
        .order('created_at', { ascending: false });

      if (status && status !== 'todos') {
        query = query.eq('status', status);
      }

      const { data, error } = await query;
      if (error) {
        res.status(500).json({ success: false, error: error.message });
        return;
      }

      res.json({ success: true, users: data || [] });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Erro ao listar usuários.' });
    }
  }

  /**
   * Aprovar usuário e criar/vincular perfil de forma transacional e idempotente
   */
  static async approveUser(req: Request, res: Response): Promise<void> {
    const userId = req.params.id;

    if (!userId) {
      res.status(400).json({ success: false, error: 'ID do usuário obrigatório.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      
      // Chamar RPC PostgreSQL 'aprovar_usuario'
      const { data: rpcData, error: rpcErr } = await client.rpc('aprovar_usuario', { p_user_id: userId });

      if (rpcErr) {
        // Fallback para update direto caso a RPC ainda não tenha sido executada
        const { error: updErr } = await client
          .from('usuarios')
          .update({ status: 'aprovado' })
          .eq('id', userId);

        if (updErr) {
          res.status(500).json({ success: false, error: updErr.message });
          return;
        }

        res.json({ success: true, message: 'Usuário aprovado com sucesso via atualização direta.' });
        return;
      }

      res.json({ success: true, result: rpcData });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Falha ao aprovar usuário.' });
    }
  }

  /**
   * Atualizar perfil e privilégios de um usuário (Ex: Professor -> Administrador)
   */
  static async updateRole(req: Request, res: Response): Promise<void> {
    const userId = req.params.id;
    const { role, permissions } = req.body;

    if (!userId || !role) {
      res.status(400).json({ success: false, error: 'ID do usuário e novo papel (role) são obrigatórios.' });
      return;
    }

    try {
      const client = getBackendSupabaseClient();
      const isMaster = role === 'admin';

      const { error } = await client
        .from('usuarios')
        .update({
          role,
          is_master_admin: isMaster,
          ...(permissions ? { permissions } : {})
        })
        .eq('id', userId);

      if (error) {
        res.status(500).json({ success: false, error: error.message });
        return;
      }

      res.json({ success: true, message: `Perfil do usuário atualizado para ${role} com sucesso.` });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err?.message || 'Erro ao atualizar perfil do usuário.' });
    }
  }
}
