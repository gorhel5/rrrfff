<?php
error_reporting(0);
mb_internal_encoding('UTF-8');

function lp_get_header($name) {
    return isset($_SERVER[$name]) ? $_SERVER[$name] : '';
}

function lp_first_ip_from_list($value) {
    // X-Forwarded-For may contain: "client, proxy1, proxy2"
    $parts = explode(',', $value);
    if (!empty($parts)) {
        return trim($parts[0]);
    }
    return trim($value);
}

function lp_get_client_ip() {
    $ip = lp_get_header('REMOTE_ADDR');

    $ip_headers = array(
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'HTTP_X_COMING_FROM',
        'HTTP_COMING_FROM',
        'HTTP_FORWARDED_FOR_IP'
    );

    foreach ($ip_headers as $header) {
        $val = lp_get_header($header);
        if ($val !== '') {
            $candidate = lp_first_ip_from_list($val);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                $ip = $candidate;
                break;
            }
        }
    }

    // final validate (REMOTE_ADDR might be empty/invalid in rare cases)
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $ip = '';
    }

    return $ip;
}

function lp_http_post($url, $data, $timeout) {
    $payload = http_build_query($data, '', '&');

    // Prefer cURL if available
    if (function_exists('curl_init') && function_exists('curl_exec')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_TIMEOUT, (int)$timeout);

        // Keep your original behavior (but note: disabling SSL verification is insecure)
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

        $result = curl_exec($ch);
        $http_code = 0;
        if (!curl_errno($ch)) {
            $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        }
        curl_close($ch);

        return array($http_code, $result);
    }

    // Fallback: file_get_contents (requires allow_url_fopen)
    if (function_exists('file_get_contents')) {
        $ua = lp_get_header('HTTP_USER_AGENT');

        $context = stream_context_create(array(
            'http' => array(
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n" .
                             "User-Agent: " . $ua . "\r\n",
                'content' => $payload,
                'timeout' => (int)$timeout
            ),
            'ssl' => array(
                'verify_peer'      => false,
                'verify_peer_name' => false
            )
        ));

        $result = @file_get_contents($url, false, $context);

        // Best-effort HTTP status from $http_response_header
        $code = 0;
        if (isset($http_response_header) && is_array($http_response_header)) {
            foreach ($http_response_header as $h) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $h, $m)) {
                    $code = (int)$m[1];
                    break;
                }
            }
        }

        return array($code, $result);
    }

    return array(0, '');
}

function lp_fetch_content($url) {
    $ua = lp_get_header('HTTP_USER_AGENT');

    // Keep your behavior (insecure SSL verify off)
    $context = stream_context_create(array(
        'http' => array(
            'header' => "User-Agent: " . $ua . "\r\n"
        ),
        'ssl' => array(
            'verify_peer'      => false,
            'verify_peer_name' => false
        )
    ));

    return @file_get_contents($url, false, $context);
}

// Build request data
$request_data = array(
    'company_id'  => '92c8cc99-90c8-4338-a32f-5de57e8fd5e7',
    'user_agent'  => lp_get_header('HTTP_USER_AGENT'),
    'referer'     => lp_get_header('HTTP_REFERER'),
    'query'       => lp_get_header('QUERY_STRING'),
    'lang'        => lp_get_header('HTTP_ACCEPT_LANGUAGE'),
    'ip_address'  => lp_get_client_ip()
);

list($status, $result) = lp_http_post('https://api.lp-cloak.com/api/verifies', $request_data, 15);

if ($status === 200 && $result !== '') {
    $body = json_decode($result, true);

    if (!is_array($body) || !isset($body['type']) || !isset($body['url'])) {
        exit('Invalid response.');
    }

    $type = $body['type'];
    $url  = $body['url'];

    if ($type === 'load') {
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            $html = lp_fetch_content($url);
            if ($html === false || $html === '') {
                exit('Offer Page Not Found.');
            }
            echo str_replace('<head>', '<head><base href="' . $url . '" />', $html);
            exit;
        }

        if (file_exists($url)) {
            $ext = strtolower(pathinfo($url, PATHINFO_EXTENSION));
            if ($ext === 'html' || $ext === 'htm') {
                $html = @file_get_contents($url);
                if ($html === false) exit('Offer Page Not Found.');
                echo $html;
                exit;
            }

            require_once($url);
            exit;
        }

        exit('Offer Page Not Found.');
    }

    if ($type === 'redirect') {
        header('Location: ' . $url, true, 302);
        exit;
    }

    if ($type === 'iframe') {
        echo '<iframe src="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" width="100%" height="100%" align="left"></iframe><style>body{padding:0;margin:0}iframe{margin:0;padding:0;border:0}</style>';
        exit;
    }

    exit('Unsupported response type.');
}

if (!function_exists('curl_init') && !ini_get('allow_url_fopen')) {
    exit('Neither cURL nor allow_url_fopen are available on the hosting.');
}

exit('Something went wrong. Please contact support.');
?>