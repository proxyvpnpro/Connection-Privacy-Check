<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ProxyVPNPro\PrivacyCheck\Network\ClientIpResolver;

final class ClientIpResolverTest extends TestCase
{
    public function testUsesRemoteAddressByDefault(): void
    {
        $resolver = new ClientIpResolver();
        self::assertSame('203.0.113.10', $resolver->resolve([
            'REMOTE_ADDR' => '203.0.113.10',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.2',
        ]));
    }

    public function testTrustsForwardedHeaderOnlyFromTrustedProxy(): void
    {
        $resolver = new ClientIpResolver(['10.0.0.1']);
        self::assertSame('198.51.100.2', $resolver->resolve([
            'REMOTE_ADDR' => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.2, 10.0.0.2',
        ]));
    }
}
