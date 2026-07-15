<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use ProxyVPNPro\PrivacyCheck\Score\ScoreCalculator;

final class ScoreCalculatorTest extends TestCase
{
    public function testScoreIsClamped(): void
    {
        $calculator = new ScoreCalculator();
        self::assertSame(65, $calculator->calculate([20, 15]));
        self::assertSame(0, $calculator->calculate([150]));
    }

    public function testVerdicts(): void
    {
        $calculator = new ScoreCalculator();
        self::assertSame('protected', $calculator->verdict(80));
        self::assertSame('partially_protected', $calculator->verdict(50));
        self::assertSame('exposed', $calculator->verdict(49));
    }
}
