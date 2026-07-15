<?php

declare(strict_types=1);

return [
    'app_name' => 'Connection Privacy Check',
    'author_name' => 'ProxyVPNPro',
    'author_url' => 'https://github.com/proxyvpnpro',
    'trusted_proxies' => [],
    'webrtc_stun_server' => 'stun:stun.l.google.com:19302',
    'score' => [
        'https_missing' => 20,
        'webrtc_public_leak' => 35,
        'webrtc_private_ip' => 10,
        'proxy_headers' => 10,
        'high_fingerprint' => 15,
        'medium_fingerprint' => 7,
        'dnt_disabled' => 3,
        'gpc_disabled' => 2,
        'cookies_disabled' => 0,
    ],
];
