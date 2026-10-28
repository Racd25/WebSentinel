# WebSentinel

**Web Security Posture Auditor** — CLI tool written in Go that audits web security configurations, detecting TLS weaknesses, missing security headers, insecure cookie flags, and information exposure.

## What it does

WebSentinel connects to any website and performs a comprehensive security posture assessment:

- **TLS audit**: Protocol versions (TLS 1.0-1.3), certificate validity and chain trust, cipher suite strength, HTTP→HTTPS redirection
- **Security headers**: HSTS, CSP (with detection of `unsafe-inline`/`unsafe-eval`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Cookie flags**: Validates `Secure`, `HttpOnly`, and `SameSite` attributes on all cookies
- **Information exposure**: Detects exposed sensitive paths (`.git`, `.env`, backups) and revealing headers (`Server`, `X-Powered-By`)

Produces an **A-F grade** (100-point score) and generates executive reports in **HTML** (color-coded severity badges) and **JSON** (structured data).

## Why I built this

As a Security Tooling Engineer, I needed a lightweight, open-source alternative to commercial web scanners (SSL Labs, Mozilla Observatory) that could run offline, integrate into CI/CD pipelines, and audit internal staging environments. WebSentinel fills that gap: a fast, dependency-free tool that runs in seconds and produces actionable findings aligned with OWASP best practices.

## Tech stack

- **Go** (concurrency, `crypto/tls`, `x509`, `net/http`, `html/template`)
- **Goroutine worker pools** for concurrent path scanning (10x faster than sequential)
- **Zero external dependencies** (standard library only)

## Installation

### Pre-built binaries

Download from [Releases](https://github.com/Racd25/WebSentinel/releases).

### Build from source

```bash
git clone https://github.com/Racd25/WebSentinel.git
cd WebSentinel
go build -o websentinel ./cmd/websentinel
