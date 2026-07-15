<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ProxyVPNPro\PrivacyCheck\Network\HeaderAnalyzer;

final class HeaderAnalyzerTest extends TestCase
{
    public function testDetectsProxyArtifacts(): void
    {
        $result = (new HeaderAnalyzer())->analyzeProxyHeaders(['HTTP_VIA' => '1.1 proxy']);
        self::assertTrue($result['detected']);
        self::assertSame('1.1 proxy', $result['headers']['via']);
    }
}
