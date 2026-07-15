<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' https://stun.l.google.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="A lightweight self-hosted browser connection privacy check.">
    <title><?= htmlspecialchars($config['app_name'], ENT_QUOTES, 'UTF-8') ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<main class="page-shell">
    <header class="hero">
        <div class="hero__content">
            <span class="eyebrow">Privacy-first connection analyzer</span>
            <h1>Connection Privacy Check</h1>
            <p>Check whether your browser exposes connection details that may reduce your privacy.</p>
            <button class="primary-button" id="start-scan" type="button">Start privacy scan</button>
        </div>
    </header>

    <section class="scan-panel" aria-live="polite">
        <div class="progress-wrap" id="progress-wrap" hidden>
            <div class="progress-track"><div class="progress-bar" id="progress-bar"></div></div>
            <p id="progress-text">Preparing scan…</p>
        </div>

        <section class="summary-card" id="summary-card" hidden>
            <div class="score-dial" id="score-dial">
                <span id="score-value">0</span>
                <small>/100</small>
            </div>
            <div>
                <span class="status-pill" id="verdict-pill">Pending</span>
                <h2 id="verdict-title">Scan not started</h2>
                <p id="verdict-message">Run the scan to analyze this connection.</p>
            </div>
        </section>

        <section class="results-grid" id="results-grid"></section>

        <section class="recommendation" id="recommendation" hidden>
            <h2>Recommendation</h2>
            <p id="recommendation-text"></p>
        </section>
    </section>
</main>

<footer class="site-footer">
    <p>No database, cookies, or persistent visitor profiling.</p>
    <p>Author: <a href="<?= htmlspecialchars($config['author_url'], ENT_QUOTES, 'UTF-8') ?>" rel="noopener noreferrer"><?= htmlspecialchars($config['author_name'], ENT_QUOTES, 'UTF-8') ?></a> · MIT License</p>
</footer>

<script src="assets/js/checker.js" defer></script>
</body>
</html>
