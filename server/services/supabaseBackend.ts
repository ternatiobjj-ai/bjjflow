import { createClient, SupabaseClient } from '@supabase/supabase-js';

// URL e chave do projeto Ternatio BJJ para o backend Express
export const BACKEND_SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || 'https://rbvyyekrsjfweewgnyuh.supabase.co';
export const BACKEND_SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || 'sb_publishable_BHPL4Bd5KL9qiURdLevMBQ_C0Ld7-D9';


let backendClient: SupabaseClient | null = null;

export function getBackendSupabaseClient(): SupabaseClient {
  if (!backendClient) {
    backendClient = createClient(BACKEND_SUPABASE_URL, BACKEND_SUPABASE_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
  }
  return backendClient;
}

/**
 * Consulta de saúde do banco de dados no backend
 */
export async function checkDatabaseHealth(): Promise<{ ok: boolean; message: string; timestamp: string }> {
  try {
    const client = getBackendSupabaseClient();
    const { error } = await client.from('usuarios').select('id').limit(1);
    if (error) {
      return { ok: false, message: error.message, timestamp: new Date().toISOString() };
    }
    return { ok: true, message: 'Conexão com o Supabase ativa e respondendo.', timestamp: new Date().toISOString() };
  } catch (err: any) {
    return { ok: false, message: err?.message || 'Erro inesperado ao consultar Supabase.', timestamp: new Date().toISOString() };
  }
}
