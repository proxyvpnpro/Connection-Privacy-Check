<?php

declare(strict_types=1);

namespace ProxyVPNPro\PrivacyCheck\Network;

final class HeaderAnalyzer
{
    public function analyzeProxyHeaders(array $server): array
    {
        $headers = [
            'via' => $this->clean($server['HTTP_VIA'] ?? null),
            'forwarded' => $this->clean($server['HTTP_FORWARDED'] ?? null),
            'x_forwarded_for' => $this->clean($server['HTTP_X_FORWARDED_FOR'] ?? null),
            'proxy_connection' => $this->clean($server['HTTP_PROXY_CONNECTION'] ?? null),
        ];

        return [
            'detected' => count(array_filter($headers, static fn (?string $value): bool => $value !== null)) > 0,
            'headers' => $headers,
        ];
    }

    public function browserHeaders(array $server): array
    {
        return [
            'user_agent' => $this->clean($server['HTTP_USER_AGENT'] ?? null),
            'accept_language' => $this->clean($server['HTTP_ACCEPT_LANGUAGE'] ?? null),
            'dnt' => $this->clean($server['HTTP_DNT'] ?? null),
            'sec_gpc' => $this->clean($server['HTTP_SEC_GPC'] ?? null),
        ];
    }

    private function clean(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        return $value === '' ? null : substr($value, 0, 512);
    }
}
