# 🥋 Ternatio BJJ - Arquitetura Full-Stack

Sistema integrado de gestão técnica, administrativa e financeira para academias de Jiu-Jitsu.

---

## 📁 Estrutura de Pastas: Separação Frontend & Backend

O projeto foi organizado com separação de responsabilidades entre **Frontend** e **Backend**:

```text
├── server/                         # 🟢 BACKEND (Node.js, Express, APIs e Banco de Dados)
│   ├── index.ts                    # Roteador central das APIs (/api)
│   ├── routes/                     # Definição das rotas HTTP
│   │   ├── auth.routes.ts          # Endpoints de login, alteração e recuperação de senha
│   │   ├── users.routes.ts         # Endpoints de listagem, aprovação e controle de papéis
│   │   └── system.routes.ts        # Endpoints de saúde (health check) e configurações
│   ├── controllers/                # Lógica de controle e regras de negócio
│   │   ├── authController.ts       # Validação de credenciais e segurança
│   │   └── usersController.ts      # Controle de aprovações e privilégios (RBAC)
│   ├── middleware/                 # Interceptadores e segurança
│   │   └── authMiddleware.ts       # Proteção de rotas administrativas
│   ├── services/                   # Serviços do servidor
│   │   └── supabaseBackend.ts      # Conexão e operações diretas com o Supabase
│   └── db/                         # Persistência e scripts SQL
│       ├── schema.sql              # Esquema DDL de tabelas, índices e funções RPC
│       └── rls-policies.sql        # Políticas de Row Level Security (RLS)
│
├── server.ts                       # 🚀 Ponto de entrada do servidor Full-Stack (Porta 3000)
│                                   # Monta as rotas /api e integra os middlewares do Vite
│
├── src/                            # 🔵 FRONTEND (React 19, TypeScript, Vite, Tailwind CSS)
│   ├── components/                 # Componentes de interface do usuário
│   │   ├── auth/                   # Modais de autenticação e troca de senha
│   │   ├── layout/                 # Layout principal, cabeçalho e menu lateral
│   │   ├── student/                # Modais de aluno e edição de atletas
│   │   ├── instructor/             # Modais de cadastro e perfil de professores
│   │   ├── classes/                # Modais de turmas e horários de aula
│   │   ├── events/                 # Modais de eventos e torneios
│   │   ├── technique/              # Modal do currículo técnico de jiu-jitsu
│   │   ├── settings/               # Aba de configurações e conexões
│   │   ├── ui/                     # Componentes base (botões, badges, logomarca)
│   │   ├── charts/                 # Gráfico radar de desenvolvimento técnico
│   │   ├── report/                 # Geração e exportação de relatórios
│   │   └── import/                 # Modal de importação em lote de planilhas CSV
│   ├── pages/                      # Telas da aplicação (rotas SPA)
│   │   ├── Login.tsx               # Tela de login, novo cadastro e recuperação
│   │   ├── Dashboard.tsx           # Visão geral e métricas do dojo
│   │   ├── Cadastros.tsx           # Hub unificado de cadastros
│   │   ├── Professores.tsx         # Gestão do corpo docente
│   │   ├── Equipe.tsx              # Gestão de alunos e tutelas
│   │   ├── AreaAluno.tsx           # Portal exclusivo do praticante
│   │   ├── Financeiro.tsx          # Gestão de mensalidades e fluxo de caixa
│   │   ├── Graduacao.tsx           # Critérios IBJJF, graus e faixas
│   │   ├── Configuracoes.tsx       # Configurações gerais e temas
│   │   ├── Aprovacoes.tsx          # Aprovação de novos cadastros
│   │   └── ...                     # Demais telas operacionais
│   ├── context/                    # Estado global da aplicação
│   │   └── BjjContext.tsx          # Provedor React com sincronização e RBAC
│   ├── services/                   # Clientes de comunicação do frontend
│   │   └── supabaseService.ts      # Cliente de persistência e operações de tela
│   ├── types/                      # Interfaces TypeScript do domínio BJJ
│   │   └── index.ts                # Modelos de dados e permissões
│   ├── data/                       # Dados iniciais e currículo base
│   │   ├── mockData.ts
│   │   └── base44Data.ts
│   ├── App.tsx                     # Roteamento central com rotas protegidas
│   ├── main.tsx                    # Renderização raiz do React DOM
│   └── index.css                   # Estilos globais e temas da academia
│
├── scripts/                        # 🛠️ Scripts auxiliares offline (Python)
├── public/                         # 📦 Arquivos estáticos públicos
└── package.json                    # ⚙️ Scripts de build e dependências
```

---

## 🚀 Como Executar

1. **Instalar dependências**:
   ```bash
   npm install
   ```

2. **Executar em Desenvolvimento (Full-Stack na porta 3000)**:
   ```bash
   npm run dev
   ```

3. **Compilar para Produção**:
   ```bash
   npm run build
   ```

4. **Executar em Produção**:
   ```bash
   npm start
   ```
