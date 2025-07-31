================================================================
# 📘 README - Vale-Transporte Automático por E-mail
================================================================

------------------------------------------------------------
# 📝 Descrição
------------------------------------------------------------
# Este projeto disponibiliza um formulário web responsivo que:
 1. Recebe dados da empresa e de vários colaboradores (nome, transporte, valor, quantidade).
 2. Gera um arquivo CSV com todos os registros enviados.
 3. Envia automaticamente o CSV por e-mail ao usuário e ao administrador, usando PHPMailer.
 4. Implementa:
    - Proteção CSRF por token.
    - Rate limiting simples via arquivo de log para evitar abusos.
    - Políticas de segurança HTTP (CSP, X-Frame-Options, X-Content-Type-Options).
    - Sanitização completa dos dados de entrada.

------------------------------------------------------------
# 🚀 Tecnologias e Dependências
------------------------------------------------------------
 - PHP 7.4+ (com suporte a random_bytes, session)
 - PHPMailer (via Composer)
 - Composer para gerenciamento de dependências
 - Variáveis de ambiente (.env)
 - Servidor web compatível com PHP (Apache, Nginx etc.)

------------------------------------------------------------
# 📋 Requisitos
------------------------------------------------------------
 1. PHP 7.4 ou superior  
 2. Composer instalado  
 3. Extensões PHP:
    - openssl
    - filter
    - mbstring
    - session
 4. Permissão de escrita em rate_limit.log e rate_limit.lock
 5. Acesso SMTP válido para envio de e-mail

------------------------------------------------------------
# ⚙️ Instalação
------------------------------------------------------------
# Clone o repositório
git clone https://github.com/SEU_USUARIO/nome-do-repo.git
cd nome-do-repo

# Instale as dependências PHP
composer install

# Crie 1 .env e edite com suas credenciais

 Exemplo de conteúdo do .env:
 SMTP_HOST=smtp.exemplo.com
 SMTP_PORT=587
 SMTP_USER=usuario@smtp.com
 SMTP_PASSWORD=sua_senha
 ADMIN_EMAIL=admin@seudominio.com
 TIMEZONE=America/Sao_Paulo

# Dê permissão de escrita nos arquivos de controle
touch rate_limit.log rate_limit.lock
chmod 666 rate_limit.log rate_limit.lock

 ------------------------------------------------------------
# 🚩 Como Usar
 ------------------------------------------------------------
 1. Acesse index.php pelo navegador (ex: http://localhost/index.php)
 2. Preencha:
    - Empresa
    - E-mail do solicitante
    - Colaboradores (vários registros: nome, transporte, valor, quantidade)
 3. Clique em "Enviar"
 4. Confira o e-mail recebido com o CSV em anexo

 ------------------------------------------------------------
# 📁 Estrutura de Pastas
 ------------------------------------------------------------
 ├── index.php           # Arquivo principal
 ├── composer.json       # Dependências PHP
 ├── rate_limit.log      # Log de requests para rate limiting
 ├── rate_limit.lock     # Lockfile para sincronização
 ├── vendor/             # Dependências via Composer
 └── .env.example        # Exemplo de variáveis de ambiente

 ------------------------------------------------------------
# 🔐 Segurança
 ------------------------------------------------------------
 - CSRF Token: geração e validação em sessão
 - CSP: cabeçalho Content-Security-Policy limitando scripts a 'self'
 - X-Frame-Options: DENY (protege contra clickjacking)
 - X-Content-Type-Options: nosniff
 - Sanitização com htmlspecialchars, filter_var e escape de CSV

 ------------------------------------------------------------
# 🤝 Contribuição
 ------------------------------------------------------------
 1. Faça um fork
 2. Crie uma branch (git checkout -b feature/minha-feature)
 3. Commit (git commit -m 'Minha feature')
 4. Push (git push origin feature/minha-feature)
 5. Abra um Pull Request
