<?php

declare(strict_types=1);

namespace ProxyVPNPro\PrivacyCheck\Score;

final class ScoreCalculator
{
    public function calculate(array $penalties): int
    {
        $total = 0;
        foreach ($penalties as $penalty) {
            if (is_numeric($penalty)) {
                $total += max(0, (int) $penalty);
            }
        }
        return max(0, min(100, 100 - $total));
    }

    public function verdict(int $score): string
    {
        return match (true) {
            $score >= 80 => 'protected',
            $score >= 50 => 'partially_protected',
            default => 'exposed',
        };
    }
}
