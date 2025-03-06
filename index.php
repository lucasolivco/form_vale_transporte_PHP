<?php
// ======================================
// SEÇÃO DE CONFIGURAÇÕES E SEGURANÇA
// ======================================

//Inicia uma sessão para manter dados do usuário entre páginas
session_start();
date_default_timezone_set('America/Sao_Paulo');

// Gera um nonce para proteção CSP (Content Security Policy). Gera um código único (nonce) para permitir scripts confiáveis.
$nonce = base64_encode(random_bytes(16));

// Define políticas de segurança via headers HTTP. Define regras de segurança para bloquear conteúdo malicioso.
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'none'; X-Content-Type-Options: nosniff; X-Frame-Options: DENY");

// Configuração de tratamento de erros
// Esconde erros do usuário final
// Registra erros em um arquivo secreto (error.log)
ini_set('display_errors', 0);
error_reporting(0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// Carrega variáveis de ambiente
require __DIR__ . '/env-loader.php';

// ======================================
// CONFIGURAÇÃO DO PHPMailer
// ======================================
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

// Gera token CSRF se não existir.
// Cria um código secreto único para cada usuário.
// Impede que outros sites enviem formulários falsos.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function sanitizeCsvValue($value) {
    return '"' . str_replace(['"', "\n", "\r"], ['""', '', ''], $value) . '"';
}

// ======================================
// LÓGICA DE PROCESSAMENTO DO FORMULÁRIO
// ======================================

// Só executa se o formulário foi enviado
// Verifica o código secreto para garantir que é um envio legítimo
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verifica token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Token CSRF inválido!');
    }

    // Sistema de rate limiting
    // Usa um arquivo para registrar os envios e evitar abusos
    $ip = ($_SERVER['REMOTE_ADDR'] == '::1') ? '127.0.0.1' : $_SERVER['REMOTE_ADDR'];
    $limite = 10;
    $arquivoLog = __DIR__ . '/rate_limit.log';
    $lockFile = __DIR__ . '/rate_limit.lock';

    // Bloqueio direto no arquivo de dados
    $handle = fopen($arquivoLog, 'c+');
    if (!$handle) {
        error_log('Falha ao abrir arquivo de log');
        die('Erro no servidor');
    }
    flock($handle, LOCK_EX);

    // Carregar e processar dados
    $dados = json_decode(stream_get_contents($handle), true) ?: [];
    $currentTimestamp = time();

    // Limpar registros antigos apenas para o IP atual
    $dados[$ip] = array_filter($dados[$ip] ?? [], function($t) use ($currentTimestamp) {
        return ($currentTimestamp - $t) <= 120;
    });

    // Verificar limite
    if (count($dados[$ip] ?? []) >= $limite) {
        $message = 'Muitas requisições. Tente novamente mais tarde.';
        $messageType = 'error';
    } else {
        $dados[$ip][] = $currentTimestamp;
        
        // Otimização: limpeza apenas periódica de IPs inativos
        if (mt_rand(0, 100) < 5) { // 5% de chance de executar a limpeza
            foreach ($dados as $key => $values) {
                if (empty($values)) unset($dados[$key]);
            }
        }

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($dados));
    }

    // Liberar lock
    flock($handle, LOCK_UN);
    fclose($handle);

    // Sanitização de dados do formulário
    // Validar Dados do Formulário
    // Remove caracteres especiais que poderiam ser maliciosos
    // Modificar a sanitização para arrays
    $empresa = htmlspecialchars($_POST['empresa'] ?? '', ENT_QUOTES, 'UTF-8');
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    
    // Novas variáveis para múltiplos registros
    $nomes = $_POST['nome'] ?? [];
    $transportes = $_POST['transporte'] ?? [];
    $valores = $_POST['valor'] ?? [];
    $quantidades = $_POST['quantidade'] ?? [];

    // Validações ajustadas para arrays
    $erro = false;
    $registros = [];
    
    // Validar cada registro
    foreach ($nomes as $index => $nome) {
        $registro = [
            'nome' => htmlspecialchars($nome, ENT_QUOTES, 'UTF-8'),
            'transporte' => htmlspecialchars($transportes[$index] ?? '', ENT_QUOTES, 'UTF-8'),
            'valorInput' => $valores[$index] ?? '',
            'quantidade' => (int)($quantidades[$index] ?? 0)
        ];

        // Validações individuais
        if (empty($registro['nome']) || empty($registro['transporte'])) {
            $erro = true;
            $message = 'Preencha todos os campos corretamente.';
        }

        if (!preg_match('/^\d{1,3}(?:\.\d{3})*,\d{2}$/', $registro['valorInput'])) {
            $erro = true;
            $message = 'Formato de valor inválido! Use "500,00"';
        }

        $registro['valor'] = (float)str_replace(['.', ','], ['', '.'], $registro['valorInput']);

        if ($registro['quantidade'] < 1) {
            $erro = true;
            $message = 'Quantidade deve ser maior que zero!';
        }

        $registros[] = $registro;
    }

    // Validações gerais
    if (!$empresa || !$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $erro = true;
        $message = 'Dados da empresa inválidos!';
    }
    {if kkkk}
    if ($erro) {
        header("Location: " . $_SERVER['PHP_SELF'] . "?message=" . urlencode($message) . "&type=" . urlencode('error'));
        exit;
    }

    // Configura conexão segura com o servidor de emails.
    // Adiciona anexo com os dados em formato CSV.
    // Envia o email para o administrador e para o usuário
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $_ENV['SMTP_HOST'];
        $mail->Port = (int)$_ENV['SMTP_PORT'];
        $mail->SMTPAuth = true;
        $mail->Username = $_ENV['SMTP_USER'];
        $mail->Password = $_ENV['SMTP_PASSWORD'];
        $mail->SMTPSecure = 'tls';
        $mail->SMTPOptions = [
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false
            ]
        ];

        // Otimizações
        $mail->SMTPKeepAlive = true;
        $mail->Timeout = 15;

        // Gerar CSV
        $dataHora = date('Y-m-d_H-i-s');
        $safeEmpresa = preg_replace('/[^a-zA-Z0-9-_\.]/', '_', $empresa);
        $safeNome = preg_replace('/[^a-zA-Z0-9-_\.]/', '_', $nome);
        $nomeArquivo = "{$safeEmpresa}_{$safeNome}_{$dataHora}.csv";

        $csvData = "Empresa,Email,Nome,Transporte,Valor (R$),Quantidade\n";
        foreach ($registros as $registro) {
            $csvData .= implode(',', [
                sanitizeCsvValue($empresa),
                sanitizeCsvValue($email),
                sanitizeCsvValue($registro['nome']),
                sanitizeCsvValue($registro['transporte']),
                sanitizeCsvValue($registro['valor']),
                sanitizeCsvValue($registro['quantidade'])
            ]) . "\n";
        }

        // Configurar e-mail
        $mail->setFrom($_ENV['SMTP_FROM'], $_ENV['SMTP_FROM_NAME']);
        if (!empty($_ENV['ADMIN_EMAIL'])) {
            $mail->addAddress($_ENV['ADMIN_EMAIL']);
        }
        $mail->addAddress($email);
        $mail->addStringAttachment($csvData, $nomeArquivo);
        $mail->isHTML(false);
        $mail->Subject = 'Novo Registro Vale-Transporte - ' . $empresa;
        $mail->Body = "Novo registro\nCliente: " . htmlspecialchars($empresa) . "\nColaborador: " . htmlspecialchars($nome);

        $mail->send();
        $message = 'Formulário enviado com sucesso!';
        $messageType = 'success';

    } catch (Exception $e) {
        error_log('Erro PHPMailer [' . date('Y-m-d H:i:s') . ']: ' . $e->getMessage() . ' | IP: ' . $_SERVER['REMOTE_ADDR']);
        $message = 'Erro ao enviar e-mail. Tente novamente mais tarde.';
        $messageType = 'error';
    }

    header("Location: " . $_SERVER['PHP_SELF'] . "?message=" . urlencode($message) . "&type=" . urlencode($messageType));
    exit;
}

// ======================================
// EXIBIÇÃO DE MENSAGENS
// ======================================

// Exibe mensagens de sucesso ou erro após o envio.
// Evita que o usuário recarregue a página e reenvie o formulário.
// Protege contra códigos maliciosos nas mensagens
if (isset($_GET['message']) && isset($_GET['type'])) {
    $message = htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
    $messageType = htmlspecialchars($_GET['type'], ENT_QUOTES, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cadastro Vale-Transporte</title>
    <style>
        :root {
            --primary:rgb(48, 175, 197);
            --primary-hover:rgb(27, 138, 158);
            --background:rgb(248, 248, 252);
            --surface: #ffffff;
            --text: #1e293b;
            --text-light: #64748b;
            --success: #16a34a;
            --danger: #dc2626;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--background);
            color: var(--text);
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1rem;
        }

        .container {
            background: var(--surface);
            padding: 2rem;
            border-radius: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 550px;
            margin: 1rem auto;
            flex-grow: 1;
            position: relative; /* Necessário para o posicionamento do logo */
        }

        .logo {
            position: absolute;
            top: 15px;  /* Ajuste a distância do topo */
            right: 20px; /* Ajuste a distância da direita */
            width: 120px;
        }

        h1 {
            font-size: 1.875rem;
            font-weight: 600;
            color: var(--text);
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
            padding-bottom: 1rem;
        }

        h1::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 3px;
            background: var(--primary);
            border-radius: 2px;
        }
    

        /* Ajustes para tablets (768px+) */
        @media (min-width: 768px) {
            .container {
                max-width: 600px;
                padding: 3rem;
            }

            h1 {
                font-size: 2.25rem;
            }

            .logout-btn {
                padding: 0.8rem 1.5rem;
                font-size: 1.1rem;
            }
        }

        /* Ajustes para desktops (1024px+) */
        @media (min-width: 1024px) {
            .container {
                max-width: 500px;
                padding: 3rem;
            }

            h1 {
                font-size: 2.5rem;
            }
        }

        /* Ajustes para mobile (480px-) */
        @media (max-width: 480px) {
            .container {
                padding: 1.5rem;
                border-radius: 1rem;
            }

            h1 {
                font-size: 1.5rem;
                margin-bottom: 1.5rem;
            }

            .logout-btn span {
                display: none;
            }

            input, select, button {
                padding: 1rem;
            }
        }

        .form-group {
            margin-bottom: 1.5rem;
            position: relative;
            display: flex;
            flex-direction: column;
            align-items: flex-start; /* Alinha todos os elementos à esquerda */
        }

        label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-light);
            margin-bottom: 0.5rem;
            width: 100%;
        }

        input, select, button {
            width: 100%; /* Garante que os elementos ocupem toda a largura */
            padding: 0.875rem;
            border: 1px solid #e2e8f0;
            border-radius: 0.75rem;
            font-size: 1rem;
            transition: all 0.2s ease;
            background: var(--surface);
            box-sizing: border-box;
        }

        input:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            outline: none;
        }

        input::placeholder {
            color: #94a3b8;
        }

        button {
            width: 100%;
            margin-top: 2rem;
            padding: 1rem;
            background: linear-gradient(135deg, var(--primary),#20B2AA);
            color: white;
            border: none;
            border-radius: 0.75rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        button:hover {
            background: linear-gradient(135deg, var(--primary-hover),rgb(42, 152, 172));
            box-shadow: 0 6px 8px -1px rgba(0, 0, 0, 0.1);
            transform: translateY(-1px);
        }

        .message {
            padding: 1rem;
            border-radius: 0.75rem;
            margin-top: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            font-size: 0.875rem;
        }

        .message.success {
            background: #f0fdf4;
            color: #16a34a;
            border: 1px solid #86efac;
        }

        .message.error {
            background: #fef2f2;
            color: #dc2626;
            border: 1px solid #fca5a5;
        }

        @media (max-width: 480px) {
            .container {
                padding: 1.5rem;
                margin: 1rem;
                border-radius: 1rem;
            }
            
            h1 {
                font-size: 1.5rem;
            }
        }

        .input-icon {
            position: absolute;
            right: 1rem;
            top: 38px;
            color: #94a3b8;
            pointer-events: none;
        }

        .link-container {
            text-align: center;
            margin-top: 2rem;
            display: grid;
            gap: 1rem;
        }

        .link-container a {
            color: var(--primary);
            text-decoration: none;
            font-size: 1rem;
            font-weight: 600;
            transition: color 0.2s ease;
        }

        .link-container a:hover {
            color: var(--primary-hover);
            text-decoration: underline;
        }

        .success {
            color: var(--success);
            font-weight: bold;
            text-align: center;
            margin-bottom: 1rem;
        }

        .error {
            color: var(--danger);
            font-weight: bold;
            text-align: center;
            margin-bottom: 1rem;
        }

        /* Estilo do modal atualizado */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            visibility: hidden;
            opacity: 0;
            transition: opacity 0.3s ease, visibility 0.3s ease;
            z-index: 1000;
            backdrop-filter: blur(4px);
        }

        .modal.show {
            visibility: visible;
            opacity: 1;
        }

        .modal-content {
            background: var(--surface);
            padding: 2.5rem 2rem 2rem;
            border-radius: 1.25rem;
            text-align: center;
            max-width: 400px;
            width: 90%;
            position: relative;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            transform: scale(0.95);
            transition: transform 0.3s ease;
        }

        .modal.show .modal-content {
            transform: scale(1);
        }

        .modal-content p {
            font-size: 1.1rem;
            margin: 1.5rem 0;
            color: var(--text);
            line-height: 1.5;
        }

        .modal-content .close {
            position: absolute;
            top: 0.75rem;
            right: 0.75rem;
            background: none;
            border: none;
            font-size: 1.8rem;
            font-weight: 300;
            color: var(--text-light);
            cursor: pointer;
            transition: all 0.2s ease;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
        }

        .modal-content .close:hover {
            color: var(--primary-hover);
            background: rgba(0, 0, 0, 0.05);
            transform: rotate(90deg);
        }

        .modal-content .close:active {
            transform: scale(0.9) rotate(90deg);
        }

        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border-left-color: var(--primary);
            animation: spin 1s ease infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loading-text {
            margin-top: 1rem;
            color: var(--text);
            font-weight: 500;
        }

        /* sessão registro */
        .registro {
            border: 1px solid #e2e8f0;
            border-radius: 0.75rem;
            padding: 1rem;
            margin-bottom: 2rem;
            position: relative;
        }

        #addRegistro {
            width: auto;
            padding: 0.75rem 1.5rem;
            margin: 1rem 0;
            background: var(--primary);
            transition: all 0.2s ease;
        }

        #addRegistro:hover {
            transform: none;
            background: var(--primary-hover);
        }

        .remove-registro {
            position: absolute;
            top: -10px;
            right: -10px;
            background: var(--danger);
            color: white;
            border: none;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .remove-registro:hover {
            background: #b91c1c;
        }

        .contador-registros {
            text-align: right;
            margin-bottom: 1rem;
            color: var(--text-light);
            font-size: 0.875rem;
        }

        .campo-invalido {
            border-color: var(--danger) !important;
            box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.1) !important;
        }

        .alerta-limite {
            color: var(--danger);
            text-align: center;
            margin: 1rem 0;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="logo canella.png" alt="Logo" class="logo">
        <h1>Registro de Transporte</h1>
        <!-- No HTML, modifique o formulário: -->
        <form method="POST" id="mainForm">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <!-- Campos da Empresa -->
            <div class="form-group">
                <label for="empresa">Nome da Empresa*</label>
                <input type="text" id="empresa" name="empresa" required>
            </div>

            <div class="form-group">
                <label for="email">Email da Empresa*</label>
                <input type="email" id="email" name="email" required>
            </div>

            <!-- Container dos Registros -->
            <div id="registrosContainer">
                <!-- Primeiro Registro -->
                <div class="registro">
                    <div class="form-group">
                        <label>Nome do Colaborador*</label>
                        <input type="text" name="nome[]" required>
                    </div>

                    <div class="form-group">
                        <label>Meio de Transporte*</label>
                        <select name="transporte[]" required>
                            <option value="">Selecione uma opção</option>
                            <option value="Carro">Carro Particular</option>
                            <option value="Barca">Barca</option>
                            <option value="Bicicleta">Bicicleta</option>
                            <option value="Ônibus">Ônibus</option>
                            <option value="Metrô">Metrô</option>
                            <option value="Trem">Trem</option>
                            <option value="Outro">Outro</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Valor (R$)*</label>
                        <input type="text" 
                            name="valor[]" 
                            placeholder="Ex: 500,00" 
                            required
                            inputmode="numeric"
                            pattern="^\d{1,3}(?:\.\d{3})*,\d{2}$">
                    </div>

                    <div class="form-group">
                        <label>Quantidade*</label>
                        <input type="number" name="quantidade[]" min="1" placeholder="Ex: 3" required>
                    </div>
                </div>
            </div>

            <!-- Alerta para limite de registros -->
            <div class="alerta-limite" id="alerta-limite">Limite máximo de registros atingido!</div>

            <button type="button" id="addRegistro">+ Adicionar Colaborador</button>
            <button type="submit">Enviar</button>
        </form>

        <!-- Modal -->
        <div class="modal" id="modal">
            <div class="modal-content">
                <button class="close" id="close-modal">&times;</button>
                <p id="modal-message"></p>
            </div>
        </div>
    </div>

    <!-- Script JavaScript com nonce CSP -->
    <script nonce="<?php echo $nonce; ?>">
        // Configuração do limite máximo de registros
        const MAX_REGISTROS = 5;

        // Função para atualizar os botões de remoção
        function updateRemoveButtons() {
            const registros = document.querySelectorAll('.registro');
            // Primeiro, remove todos os botões de remoção já existentes
            registros.forEach(registro => {
                const btnExistente = registro.querySelector('.remove-registro');
                if (btnExistente) {
                    btnExistente.remove();
                }
            });
            // Se houver mais de um registro, adiciona o botão de remoção em cada um
            if (registros.length > 1) {
                registros.forEach(registro => {
                    const btnRemove = document.createElement('button');
                    btnRemove.type = 'button';
                    btnRemove.classList.add('remove-registro');
                    btnRemove.textContent = '×';
                    btnRemove.addEventListener('click', function() {
                        registro.remove();
                        updateRemoveButtons();
                        checkLimiteRegistros();
                    });
                    registro.appendChild(btnRemove);
                });
            }
        }
        // Função para verificar e exibir mensagem de limite de registros
        function checkLimiteRegistros() {
            const registros = document.querySelectorAll('.registro');
            const alerta = document.getElementById('alerta-limite');
            if (registros.length >= MAX_REGISTROS) {
                alerta.style.display = 'block';
                return false;
            } else {
                alerta.style.display = 'none';
                return true;
            }
        }

        // Inicializa os botões de remoção na carga inicial
        updateRemoveButtons();

        // Evento para adicionar novo registro
        document.getElementById('addRegistro').addEventListener('click', function() {
            if (!checkLimiteRegistros()) {
                return;
            }
            const container = document.getElementById('registrosContainer');
            // Clona o primeiro registro
            const novoRegistro = container.children[0].cloneNode(true);
            
            // Limpar valores dos inputs e selects
            novoRegistro.querySelectorAll('input, select').forEach(element => {
                if (element.tagName === 'INPUT') element.value = '';
                if (element.tagName === 'SELECT') element.selectedIndex = 0;
            });

            // Reaplicar máscara de valor
            novoRegistro.querySelector('input[name="valor[]"]').addEventListener('input', mascaraValor);
            
            container.appendChild(novoRegistro);
            updateRemoveButtons();
            checkLimiteRegistros();
        });

        // Máscara para o campo de valor
        function mascaraValor(e) {
            let value = e.target.value.replace(/\D/g, '');
            
            // Adiciona zeros à esquerda para garantir pelo menos "0,00"
            if (value.length === 0) value = '000';
            if (value.length === 1) value = '00' + value;
            if (value.length === 2) value = '0' + value;

            // Formatação dos dígitos
            const integerPart = value.slice(0, -2).replace(/^0+/, '') || '0';
            const decimalPart = value.slice(-2);
            
            // Adiciona separadores de milhar
            const formattedInteger = integerPart.replace(/\B(?=(\d{3})+(?!\d))/g, '.');
            
            e.target.value = formattedInteger + ',' + decimalPart;
        }

        document.querySelectorAll('input[name="valor[]"]').forEach(input => {
            input.addEventListener('input', mascaraValor);
        });

        // Lógica de exibição do modal para feedback de envio
        const message = "<?php echo $message; ?>";
        const messageType = "<?php echo $messageType; ?>";

        if (message) {
            const modal = document.getElementById('modal');
            const modalMessage = document.getElementById('modal-message');
            modalMessage.textContent = message;

            // Aplica estilos de acordo com o tipo de mensagem
            modalMessage.style.color = messageType === 'success' ? 'var(--success)' : 'var(--danger)';

            modal.classList.add('show');

            // Fechar o modal ao clicar no "X"
            document.getElementById('close-modal').addEventListener('click', () => {
                modal.classList.remove('show');
            });

            // Fechar o modal ao clicar fora do conteúdo
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                }
            });
        }

        // Exibe loading ao enviar o formulário
        document.querySelector('form').addEventListener('submit', function(e) {
            const modal = document.getElementById('modal');
            const modalContent = document.querySelector('.modal-content');
            
            // Exibe o loading
            modalContent.innerHTML = `
                <div style="padding: 20px; text-align: center;">
                    <div class="spinner"></div>
                    <div class="loading-text">Enviando formulário...</div>
                </div>
            `;
            modal.classList.add('show');
        });

        <?php include 'script.js'; ?>
    </script>
</body>
</html>
