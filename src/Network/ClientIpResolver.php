<?php

declare(strict_types=1);

namespace ProxyVPNPro\PrivacyCheck\Network;

final class ClientIpResolver
{
    public function __construct(private readonly array $trustedProxies = [])
    {
    }

    public function resolve(array $server): string
    {
        $remoteAddress = trim((string) ($server['REMOTE_ADDR'] ?? ''));
        if (!filter_var($remoteAddress, FILTER_VALIDATE_IP)) {
            return 'unknown';
        }

        if (!in_array($remoteAddress, $this->trustedProxies, true)) {
            return $remoteAddress;
        }

        foreach ($this->forwardedCandidates($server) as $candidate) {
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return $remoteAddress;
    }

    private function forwardedCandidates(array $server): array
    {
        $forwardedFor = trim((string) ($server['HTTP_X_FORWARDED_FOR'] ?? ''));
        return $forwardedFor === '' ? [] : array_map('trim', explode(',', $forwardedFor));
    }
}
