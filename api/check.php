<?php

declare(strict_types=1);

use ProxyVPNPro\PrivacyCheck\Http\JsonResponse;
use ProxyVPNPro\PrivacyCheck\Network\ClientIpResolver;
use ProxyVPNPro\PrivacyCheck\Network\HeaderAnalyzer;
use ProxyVPNPro\PrivacyCheck\Network\HttpsDetector;

require dirname(__DIR__) . '/bootstrap.php';
$config = require dirname(__DIR__) . '/config.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    JsonResponse::send([
        'status' => 'error',
        'code' => 'METHOD_NOT_ALLOWED',
        'message' => 'Only GET requests are allowed.',
    ], 405);
}

$trustedProxies = $config['trusted_proxies'] ?? [];
$ip = (new ClientIpResolver($trustedProxies))->resolve($_SERVER);
$headers = new HeaderAnalyzer();

JsonResponse::send([
    'status' => 'ok',
    'data' => [
        'ip' => $ip,
        'ip_version' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 6 : 4,
        'https' => (new HttpsDetector($trustedProxies))->detect($_SERVER),
        'tls_protocol' => $_SERVER['SSL_PROTOCOL'] ?? null,
        'tls_cipher' => $_SERVER['SSL_CIPHER'] ?? null,
        'proxy_headers' => $headers->analyzeProxyHeaders($_SERVER),
        'request_headers' => $headers->browserHeaders($_SERVER),
        'webrtc_stun_server' => $config['webrtc_stun_server'],
        'score_weights' => $config['score'],
        'generated_at' => gmdate(DATE_ATOM),
    ],
]);
