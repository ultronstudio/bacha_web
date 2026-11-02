<?php
declare(strict_types=1);

date_default_timezone_set('Europe/Prague');

function jsonResponse(int $status, bool $ok, string $message): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');

    echo json_encode(
        [
            'ok' => $ok,
            'message' => $message,
        ],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function clientIp(): string
{
    if (getenv('TRUST_CLOUDFLARE') === '1') {
        $cloudflareIp = trim(
            (string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '')
        );

        if (
            $cloudflareIp !== ''
            && filter_var($cloudflareIp, FILTER_VALIDATE_IP)
        ) {
            return $cloudflareIp;
        }
    }

    $remoteIp = trim(
        (string)($_SERVER['REMOTE_ADDR'] ?? '')
    );

    return filter_var($remoteIp, FILTER_VALIDATE_IP)
        ? $remoteIp
        : 'unknown';
}

function enforceRateLimit(
    string $ip,
    int $limit = 5,
    int $windowSeconds = 900
): void {
    $directory = rtrim(
        sys_get_temp_dir(),
        DIRECTORY_SEPARATOR
    )
        . DIRECTORY_SEPARATOR
        . 'bacha-testing-interest-rate-limit';

    if (
        !is_dir($directory)
        && !@mkdir($directory, 0700, true)
        && !is_dir($directory)
    ) {
        error_log(
            'Bacha API: nelze vytvořit adresář pro rate limit.'
        );

        jsonResponse(
            503,
            false,
            'Formulář je dočasně nedostupný.'
        );
    }

    // Neukládáme IP v otevřeném tvaru.
    $file = $directory
        . DIRECTORY_SEPARATOR
        . hash('sha256', $ip)
        . '.json';

    $handle = @fopen($file, 'c+');

    if ($handle === false) {
        error_log(
            'Bacha API: nelze otevřít rate-limit soubor.'
        );

        jsonResponse(
            503,
            false,
            'Formulář je dočasně nedostupný.'
        );
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            jsonResponse(
                503,
                false,
                'Formulář je dočasně nedostupný.'
            );
        }

        $raw = stream_get_contents($handle);
        $timestamps = json_decode(
            $raw ?: '[]',
            true
        );

        if (!is_array($timestamps)) {
            $timestamps = [];
        }

        $now = time();
        $minimumTimestamp = $now - $windowSeconds;

        $timestamps = array_values(
            array_filter(
                $timestamps,
                static fn ($timestamp): bool =>
                    is_int($timestamp)
                    && $timestamp >= $minimumTimestamp
            )
        );

        if (count($timestamps) >= $limit) {
            flock($handle, LOCK_UN);
            fclose($handle);

            jsonResponse(
                429,
                false,
                'Příliš mnoho pokusů. Zkuste to prosím později.'
            );
        }

        $timestamps[] = $now;

        ftruncate($handle, 0);
        rewind($handle);

        fwrite(
            $handle,
            json_encode(
                $timestamps,
                JSON_THROW_ON_ERROR
            )
        );

        fflush($handle);
        flock($handle, LOCK_UN);
    } catch (Throwable $exception) {
        error_log(
            'Bacha API rate-limit error: '
            . $exception->getMessage()
        );

        jsonResponse(
            503,
            false,
            'Formulář je dočasně nedostupný.'
        );
    } finally {
        if (is_resource($handle)) {
            fclose($handle);
        }
    }
}

function verifyRecaptcha(
    string $token,
    string $ip
): bool {
    $secret = trim(
        (string)getenv('RECAPTCHA_SECRET_KEY')
    );

    if ($secret === '') {
        throw new RuntimeException(
            'Chybí RECAPTCHA_SECRET_KEY.'
        );
    }

    $curl = curl_init(
        'https://www.google.com/recaptcha/api/siteverify'
    );

    if ($curl === false) {
        throw new RuntimeException(
            'Nelze inicializovat cURL.'
        );
    }

    curl_setopt_array(
        $curl,
        [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'secret' => $secret,
                'response' => $token,
                'remoteip' => $ip !== 'unknown'
                    ? $ip
                    : '',
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
            ],
        ]
    );

    $body = curl_exec($curl);
    $status = (int)curl_getinfo(
        $curl,
        CURLINFO_RESPONSE_CODE
    );
    $error = curl_error($curl);

    curl_close($curl);

    if ($body === false) {
        throw new RuntimeException(
            'Ověření reCAPTCHA selhalo: ' . $error
        );
    }

    if ($status < 200 || $status >= 300) {
        return false;
    }

    $result = json_decode(
        (string)$body,
        true
    );

    if (
        !is_array($result)
        || empty($result['success'])
    ) {
        return false;
    }

    $expectedHostname = trim(
        (string)(
            getenv('RECAPTCHA_EXPECTED_HOSTNAME')
            ?: 'bacha.petrvurm.cz'
        )
    );

    if (
        $expectedHostname !== ''
        && isset($result['hostname'])
        && !hash_equals(
            $expectedHostname,
            (string)$result['hostname']
        )
    ) {
        return false;
    }

    return true;
}

function sendTestingInterestMail(
    string $mail
): void {
    $apiKey = trim(
        (string)getenv('RESEND_API_KEY')
    );

    if ($apiKey === '') {
        throw new RuntimeException(
            'Chybí RESEND_API_KEY.'
        );
    }

    $submittedAt = date(
        'd. m. Y H:i:s T'
    );

    $text = implode(
        PHP_EOL,
        [
            'Nový zájem o uzavřené testování Bacha!',
            '',
            'Na webu Bacha! byl vyplněn formulář se zájmem o uzavřené testování.',
            '',
            'Google účet / e-mail:',
            $mail,
            '',
            'Odesláno:',
            $submittedAt,
        ]
    );

    $payload = [
        'from' => 'Bacha! <bacha@petrvurm.cz>',
        'to' => [
            'kontakt@petrvurm.cz',
        ],
        'reply_to' => $mail,
        'subject' => 'Bacha! – zájem o uzavřené testování',
        'text' => $text,
        'tags' => [
            [
                'name' => 'source',
                'value' => 'bacha_test_interest',
            ],
        ],
    ];

    $curl = curl_init(
        'https://api.resend.com/emails'
    );

    if ($curl === false) {
        throw new RuntimeException(
            'Nelze inicializovat cURL.'
        );
    }

    curl_setopt_array(
        $curl,
        [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode(
                $payload,
                JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_UNICODE
            ),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $apiKey,
                'Content-Type: application/json',
                'Accept: application/json',
            ],
        ]
    );

    $body = curl_exec($curl);
    $status = (int)curl_getinfo(
        $curl,
        CURLINFO_RESPONSE_CODE
    );
    $error = curl_error($curl);

    curl_close($curl);

    if ($body === false) {
        throw new RuntimeException(
            'Resend request selhal: ' . $error
        );
    }

    if ($status < 200 || $status >= 300) {
        error_log(
            'Bacha API Resend error HTTP '
            . $status
            . ': '
            . mb_substr((string)$body, 0, 1000)
        );

        throw new RuntimeException(
            'Resend odmítl požadavek.'
        );
    }
}

function handleSend(): never
{
    if (
        ($_SERVER['REQUEST_METHOD'] ?? '')
        !== 'POST'
    ) {
        header('Allow: POST');

        jsonResponse(
            405,
            false,
            'Tato akce přijímá pouze POST požadavky.'
        );
    }

    $contentLength = (int)(
        $_SERVER['CONTENT_LENGTH'] ?? 0
    );

    if ($contentLength > 16384) {
        jsonResponse(
            413,
            false,
            'Požadavek je příliš velký.'
        );
    }

    $expectedOrigin = rtrim(
        (string)(
            getenv('APP_ORIGIN')
            ?: 'https://bacha.petrvurm.cz'
        ),
        '/'
    );

    $requestOrigin = rtrim(
        (string)(
            $_SERVER['HTTP_ORIGIN'] ?? ''
        ),
        '/'
    );

    if (
        $requestOrigin !== ''
        && !hash_equals(
            $expectedOrigin,
            $requestOrigin
        )
    ) {
        jsonResponse(
            403,
            false,
            'Požadavek pochází z nepovoleného webu.'
        );
    }

    $ip = clientIp();
    enforceRateLimit($ip);

    // Honeypot.
    if (
        trim((string)($_POST['website'] ?? ''))
        !== ''
    ) {
        jsonResponse(
            200,
            true,
            'Díky. Zájem o testování byl odeslán.'
        );
    }

    $mail = trim(
        (string)($_POST['mail'] ?? '')
    );

    if (
        $mail === ''
        || strlen($mail) > 254
        || !filter_var(
            $mail,
            FILTER_VALIDATE_EMAIL
        )
    ) {
        jsonResponse(
            422,
            false,
            'Zadejte platnou e-mailovou adresu.'
        );
    }

    $captchaToken = trim(
        (string)(
            $_POST['g-recaptcha-response']
            ?? ''
        )
    );

    if ($captchaToken === '') {
        jsonResponse(
            422,
            false,
            'Potvrďte prosím reCAPTCHA.'
        );
    }

    try {
        if (
            !verifyRecaptcha(
                $captchaToken,
                $ip
            )
        ) {
            jsonResponse(
                422,
                false,
                'reCAPTCHA se nepodařilo ověřit. Zkuste to prosím znovu.'
            );
        }

        sendTestingInterestMail($mail);

        jsonResponse(
            200,
            true,
            'Díky. Zájem o uzavřené testování byl odeslán.'
        );
    } catch (Throwable $exception) {
        error_log(
            'Bacha API error: '
            . $exception->getMessage()
        );

        jsonResponse(
            500,
            false,
            'Zájem se teď nepodařilo odeslat. Zkuste to prosím později.'
        );
    }
}

$action = trim(
    (string)($_GET['akce'] ?? '')
);

switch ($action) {
    case 'odeslat':
        handleSend();

    default:
        jsonResponse(
            404,
            false,
            'Neznámá API akce.'
        );
}
