# Connection Privacy Check

A lightweight, self-hosted browser connection privacy analyzer built with PHP 8.1+ and vanilla JavaScript.

**Author:** [ProxyVPNPro](https://github.com/proxyvpnpro)  
**License:** MIT

## Features

- Public IP and IP-version detection
- HTTPS and available TLS metadata
- WebRTC public/private IP exposure checks
- Proxy-related HTTP header analysis
- Local browser fingerprinting-surface estimate
- DNT and Global Privacy Control reporting
- Privacy score with clear recommendations
- No database, cookies, analytics, or persistent visitor profiles
- Responsive dark/light interface

## Quick start

```bash
php -S 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`.

## Docker

```bash
docker compose up --build
```

Open `http://localhost:8080`.

## Shared hosting

Upload all project files while preserving the directory structure. Set the document root to the project directory and use PHP 8.1 or newer. HTTPS is strongly recommended.

## Reverse proxy

`X-Forwarded-For` and `X-Forwarded-Proto` are trusted only when the connecting proxy IP is explicitly listed in `config.php` under `trusted_proxies`.

## Privacy note

The project performs checks in memory and does not intentionally persist visitor results. Standard web-server access logs may still contain IP addresses unless disabled by the operator.

## Development

```bash
composer install
composer lint
composer test
```

## Limitations

This lightweight release does not include authoritative DNS-leak infrastructure, GeoIP databases, or commercial VPN-detection APIs. A visible public IP alone is normal internet behavior and is not proof of compromise.
