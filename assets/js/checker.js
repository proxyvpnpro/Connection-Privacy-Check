'use strict';

const state = {
  server: null,
  checks: [],
};

const elements = {
  startButton: document.querySelector('#start-scan'),
  progressWrap: document.querySelector('#progress-wrap'),
  progressBar: document.querySelector('#progress-bar'),
  progressText: document.querySelector('#progress-text'),
  summaryCard: document.querySelector('#summary-card'),
  scoreValue: document.querySelector('#score-value'),
  scoreDial: document.querySelector('#score-dial'),
  verdictPill: document.querySelector('#verdict-pill'),
  verdictTitle: document.querySelector('#verdict-title'),
  verdictMessage: document.querySelector('#verdict-message'),
  resultsGrid: document.querySelector('#results-grid'),
  recommendation: document.querySelector('#recommendation'),
  recommendationText: document.querySelector('#recommendation-text'),
};

elements.startButton.addEventListener('click', runScan);

async function runScan() {
  elements.startButton.disabled = true;
  elements.resultsGrid.innerHTML = '';
  elements.summaryCard.hidden = true;
  elements.recommendation.hidden = true;
  showProgress(5, 'Checking server-visible connection details…');

  try {
    const response = await fetch('api/check.php', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });

    const payload = await response.json();
    if (!response.ok || payload.status !== 'ok') {
      throw new Error(payload.message || 'The server check failed.');
    }

    state.server = payload.data;
    showProgress(25, 'Running browser privacy checks…');

    const [webrtc, fingerprint, browserPrivacy] = await Promise.all([
      checkWebRtc(payload.data.ip, payload.data.webrtc_stun_server),
      checkFingerprint(),
      checkBrowserPrivacy(),
    ]);

    showProgress(75, 'Calculating your privacy score…');

    state.checks = [
      createHttpsCheck(payload.data),
      createIpCheck(payload.data),
      webrtc,
      createProxyHeaderCheck(payload.data.proxy_headers),
      fingerprint,
      browserPrivacy,
    ];

    const result = calculateScore(state.checks, payload.data.score_weights);
    renderResults(state.checks, result);
    showProgress(100, 'Scan complete.');

    window.setTimeout(() => {
      elements.progressWrap.hidden = true;
    }, 500);
  } catch (error) {
    showProgress(100, error instanceof Error ? error.message : 'Unexpected scan error.');
  } finally {
    elements.startButton.disabled = false;
  }
}

function createHttpsCheck(server) {
  return {
    id: 'https',
    title: 'HTTPS connection',
    status: server.https ? 'pass' : 'fail',
    summary: server.https
      ? 'This page is delivered through an encrypted HTTPS connection.'
      : 'This page is not using HTTPS, so data sent to it may be exposed.',
    details: server.https
      ? `TLS: ${server.tls_protocol || 'version unavailable'}${server.tls_cipher ? ` · ${server.tls_cipher}` : ''}`
      : 'Install a valid TLS certificate and redirect all HTTP traffic to HTTPS.',
    penaltyKey: server.https ? null : 'https_missing',
  };
}

function createIpCheck(server) {
  return {
    id: 'ip',
    title: 'Public IP address',
    status: 'info',
    summary: `Websites can see ${server.ip}.`,
    details: `IP version: IPv${server.ip_version}. A VPN normally replaces this address with the VPN server address.`,
    penaltyKey: null,
  };
}

function createProxyHeaderCheck(proxyHeaders) {
  return {
    id: 'proxy-headers',
    title: 'Proxy header exposure',
    status: proxyHeaders.detected ? 'warn' : 'pass',
    summary: proxyHeaders.detected
      ? 'One or more proxy-related HTTP headers were detected.'
      : 'No obvious proxy-related headers were exposed.',
    details: proxyHeaders.detected
      ? 'A transparent or misconfigured proxy may reveal routing information to websites.'
      : 'The request did not contain Via, Forwarded, X-Forwarded-For, or Proxy-Connection headers.',
    penaltyKey: proxyHeaders.detected ? 'proxy_headers' : null,
  };
}

async function checkWebRtc(serverIp, stunServer) {
  if (!window.RTCPeerConnection) {
    return {
      id: 'webrtc',
      title: 'WebRTC exposure',
      status: 'pass',
      summary: 'WebRTC is unavailable or blocked in this browser.',
      details: 'Blocking WebRTC prevents ICE candidate IP exposure.',
      penaltyKey: null,
    };
  }

  const publicIps = new Set();
  const privateIps = new Set();
  let mdnsDetected = false;

  try {
    const peer = new RTCPeerConnection({ iceServers: [{ urls: stunServer }] });
    peer.createDataChannel('privacy-check');

    peer.addEventListener('icecandidate', (event) => {
      if (!event.candidate) return;
      const candidate = event.candidate.candidate || '';
      const values = candidate.split(' ');
      const address = values[4] || '';

      if (address.endsWith('.local')) {
        mdnsDetected = true;
      } else if (isPrivateIp(address)) {
        privateIps.add(address);
      } else if (isIp(address)) {
        publicIps.add(address);
      }
    });

    const offer = await peer.createOffer();
    await peer.setLocalDescription(offer);
    await wait(3000);
    peer.close();
  } catch (error) {
    return {
      id: 'webrtc',
      title: 'WebRTC exposure',
      status: 'pass',
      summary: 'WebRTC candidates could not be collected.',
      details: 'WebRTC appears blocked or restricted, which reduces IP exposure.',
      penaltyKey: null,
    };
  }

  const differentPublicIp = [...publicIps].some((ip) => ip !== serverIp);
  if (differentPublicIp) {
    return {
      id: 'webrtc',
      title: 'WebRTC exposure',
      status: 'fail',
      summary: 'WebRTC revealed a public IP different from the server-visible IP.',
      details: `Detected public candidates: ${[...publicIps].join(', ')}. This may indicate a VPN or proxy leak.`,
      penaltyKey: 'webrtc_public_leak',
    };
  }

  if (privateIps.size > 0) {
    return {
      id: 'webrtc',
      title: 'WebRTC exposure',
      status: 'warn',
      summary: 'WebRTC exposed one or more private network addresses.',
      details: `Private candidates: ${[...privateIps].join(', ')}. This is less serious than a public IP leak but increases local-network exposure.`,
      penaltyKey: 'webrtc_private_ip',
    };
  }

  return {
    id: 'webrtc',
    title: 'WebRTC exposure',
    status: 'pass',
    summary: 'No different public IP was exposed through WebRTC.',
    details: mdnsDetected
      ? 'Local addresses were protected with mDNS masking.'
      : publicIps.size > 0
        ? `Detected public candidate matches the server-visible IP: ${[...publicIps].join(', ')}.`
        : 'No usable IP candidates were returned.',
    penaltyKey: null,
  };
}

async function checkFingerprint() {
  const canvasHash = await getCanvasHash();
  const values = {
    screen: `${window.screen.width}×${window.screen.height}×${window.screen.colorDepth}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
    platform: navigator.platform || 'unknown',
    cpu: navigator.hardwareConcurrency || 'unknown',
    memory: navigator.deviceMemory || 'unknown',
    canvas: canvasHash,
  };

  let points = 0;
  if (canvasHash !== 'blocked') points += 2;
  if (navigator.hardwareConcurrency) points += 1;
  if (navigator.deviceMemory) points += 1;
  if (window.screen.colorDepth) points += 1;

  const level = points >= 5 ? 'high' : points >= 3 ? 'medium' : 'low';

  return {
    id: 'fingerprint',
    title: 'Browser fingerprinting surface',
    status: level === 'high' ? 'warn' : 'pass',
    summary: `${capitalize(level)} fingerprinting surface detected.`,
    details: `Screen: ${values.screen} · Timezone: ${values.timezone} · Platform: ${values.platform} · CPU threads: ${values.cpu} · Memory: ${values.memory} GB · Canvas: ${values.canvas}`,
    penaltyKey: level === 'high' ? 'high_fingerprint' : level === 'medium' ? 'medium_fingerprint' : null,
  };
}

async function checkBrowserPrivacy() {
  const dnt = navigator.doNotTrack === '1' || window.doNotTrack === '1';
  const gpc = navigator.globalPrivacyControl === true;
  const cookies = navigator.cookieEnabled;

  const missing = [];
  if (!dnt) missing.push('DNT');
  if (!gpc) missing.push('GPC');

  return {
    id: 'browser-privacy',
    title: 'Browser privacy signals',
    status: missing.length === 0 ? 'pass' : 'warn',
    summary: missing.length === 0
      ? 'DNT and Global Privacy Control are enabled.'
      : `Missing privacy signals: ${missing.join(', ')}.`,
    details: `Do Not Track: ${dnt ? 'enabled' : 'disabled'} · Global Privacy Control: ${gpc ? 'enabled' : 'disabled'} · Cookies: ${cookies ? 'enabled' : 'disabled'}`,
    penaltyKeys: [
      ...(!dnt ? ['dnt_disabled'] : []),
      ...(!gpc ? ['gpc_disabled'] : []),
    ],
  };
}

function calculateScore(checks, weights) {
  let penalty = 0;

  checks.forEach((check) => {
    if (check.penaltyKey && weights[check.penaltyKey]) {
      penalty += Number(weights[check.penaltyKey]);
    }

    if (Array.isArray(check.penaltyKeys)) {
      check.penaltyKeys.forEach((key) => {
        penalty += Number(weights[key] || 0);
      });
    }
  });

  const score = Math.max(0, Math.min(100, 100 - penalty));

  if (score >= 80) {
    return {
      score,
      className: 'protected',
      pill: 'Protected',
      title: 'Your connection has strong basic privacy protections',
      message: 'No major browser-level IP leak was detected. A VPN is optional if you want to hide your public IP from websites and your browsing destinations from your network provider.',
      recommendation: 'A VPN is optional for this connection. Continue using HTTPS and keep your browser privacy settings enabled.',
    };
  }

  if (score >= 50) {
    return {
      score,
      className: 'partial',
      pill: 'Partially protected',
      title: 'Some connection details are exposed',
      message: 'Your browser exposes information that can reduce privacy. A VPN may help hide your public IP, but browser settings still matter.',
      recommendation: 'Consider using a reputable VPN and review the warning cards below, especially WebRTC and proxy-header exposure.',
    };
  }

  return {
    score,
    className: 'exposed',
    pill: 'VPN recommended',
    title: 'Your connection appears exposed',
    message: 'One or more major privacy checks failed. Your real network path or browser IP information may be visible.',
    recommendation: 'A reputable VPN is strongly recommended. After connecting, repeat this scan and confirm that WebRTC does not reveal a different public IP.',
  };
}

function renderResults(checks, result) {
  elements.summaryCard.hidden = false;
  elements.recommendation.hidden = false;
  elements.scoreValue.textContent = String(result.score);
  elements.scoreDial.className = `score-dial score-dial--${result.className}`;
  elements.verdictPill.className = `status-pill status-pill--${result.className}`;
  elements.verdictPill.textContent = result.pill;
  elements.verdictTitle.textContent = result.title;
  elements.verdictMessage.textContent = result.message;
  elements.recommendationText.textContent = result.recommendation;

  checks.forEach((check) => {
    const card = document.createElement('article');
    card.className = `result-card result-card--${check.status}`;
    card.innerHTML = `
      <div class="result-card__header">
        <span class="result-icon" aria-hidden="true">${iconForStatus(check.status)}</span>
        <div>
          <h3>${escapeHtml(check.title)}</h3>
          <p>${escapeHtml(check.summary)}</p>
        </div>
      </div>
      <details>
        <summary>What this means</summary>
        <p>${escapeHtml(check.details)}</p>
      </details>
    `;
    elements.resultsGrid.appendChild(card);
  });
}

function showProgress(percent, text) {
  elements.progressWrap.hidden = false;
  elements.progressBar.style.width = `${percent}%`;
  elements.progressText.textContent = text;
}

async function getCanvasHash() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 240;
    canvas.height = 60;
    const context = canvas.getContext('2d');
    if (!context) return 'blocked';

    context.textBaseline = 'top';
    context.font = '16px Arial';
    context.fillText('Connection Privacy Check 123', 4, 4);
    context.fillRect(20, 30, 100, 12);

    const bytes = new TextEncoder().encode(canvas.toDataURL());
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 16);
  } catch (error) {
    return 'blocked';
  }
}

function isPrivateIp(value) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(value)
    || /^fc/i.test(value)
    || /^fd/i.test(value)
    || /^fe80:/i.test(value);
}

function isIp(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':');
}

function iconForStatus(status) {
  return {
    pass: '✓',
    warn: '!',
    fail: '×',
    info: 'i',
  }[status] || '?';
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value) {
  const element = document.createElement('div');
  element.textContent = String(value);
  return element.innerHTML;
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}
