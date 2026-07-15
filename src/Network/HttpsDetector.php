<?php

declare(strict_types=1);

namespace ProxyVPNPro\PrivacyCheck\Network;

final class HttpsDetector
{
    public function __construct(private readonly array $trustedProxies = [])
    {
    }

    public function detect(array $server): bool
    {
        $https = strtolower((string) ($server['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off') {
            return true;
        }

        if ((string) ($server['SERVER_PORT'] ?? '') === '443') {
            return true;
        }

        $remoteAddress = (string) ($server['REMOTE_ADDR'] ?? '');
        return in_array($remoteAddress, $this->trustedProxies, true)
            && strtolower((string) ($server['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    }
}
