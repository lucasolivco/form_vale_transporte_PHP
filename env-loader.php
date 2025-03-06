<?php
function loadEnv($path) {
    if (!file_exists($path)) {
        throw new Exception('.env file not found');
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        // Ignora comentários e linhas inválidas
        if (strpos(trim($line), '#') === 0 || strpos($line, '=') === false) {
            continue;
        }

        // Divide a linha em chave e valor
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);

        // Define a variável de ambiente
        if (!array_key_exists($key, $_ENV)) {
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }
}

// Carregar o arquivo .env
loadEnv(__DIR__ . '/.env');