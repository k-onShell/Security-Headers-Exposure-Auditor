# Security Headers & Exposure Auditor

A professional, lightweight, production-grade CLI security auditing tool built in Python 3.10+ designed for penetration testers, security engineers, and developers.

## Features

1. **HTTP Security Headers Inspection (`headers_auditor.py`)**:
   - Evaluates missing or insecure Content Security Policy (CSP), enforcing `unsafe-inline` / `unsafe-eval` checks.
   - Inspects Strict-Transport-Security (HSTS) `max-age` thresholds and `includeSubDomains`.
   - Checks `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
   - Detects information disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).

2. **Active CORS Misconfiguration Testing (`cors_tester.py`)**:
   - Sends crafted HTTP `Origin` payloads (arbitrary external domains, `null`, prefix/suffix domain bypasses, and subdomain pre-pending).
   - Identifies high-risk wildcard origins (`*`) combined with `Access-Control-Allow-Credentials: true`.
   - Detects insecure dynamic origin reflection.

3. **Asynchronous Sensitive File Prober (`exposure_scanner.py`)**:
   - Scans for environment/config files (`.env`, `docker-compose.yml`, `wp-config.php.bak`), version control artifacts (`.git/HEAD`, `.git/config`), and backups (`backup.zip`, `backup.sql`).
   - **Smart False-Positive Filtering (Soft-404 & Signature Matching)**: Establishes a baseline response using random paths and validates findings against content signatures and MIME types.

4. **Multi-Format Reporting (`reporter.py`)**:
   - Rich terminal tables grouped by severity.
   - Structured JSON exports for CI/CD pipeline integration.
   - Standalone dark-themed HTML dashboard reports.

---

## Installation

1. Clone or navigate to the repository directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Examples

### 1. Audit a Single Target URL
```bash
python cli.py --target https://example.com
```

### 2. Audit with JSON and HTML Report Export
```bash
python cli.py --target https://example.com --json report.json --html report.html
```

### 3. Bulk Audit from a Target List File
```bash
python cli.py --list targets.txt --json bulk_results.json
```

### 4. Disable SSL Verification (for testing internal/staging targets)
```bash
python cli.py --target https://staging.local --no-verify-ssl
```

---

## Command-Line Options

```
Options:
  -t, --target TEXT        Single target URL to audit (e.g. https://example.com)
  -l, --list TEXT          Path to a text file containing a list of target URLs (one per line)
  --verify-ssl / --no-verify-ssl
                           Enable or disable SSL/TLS certificate verification [default: verify-ssl]
  --timeout FLOAT          HTTP request timeout in seconds [default: 10.0]
  -c, --concurrency INTEGER
                           Maximum concurrent requests for exposure scanner [default: 50]
  -j, --json TEXT          Path to export structured JSON report
  --html TEXT              Path to export standalone dark-themed HTML dashboard report
  --help                   Show this message and exit
```

---

## Project Architecture

- `cli.py`: Typer CLI interface & Rich formatting.
- `headers_auditor.py`: Security headers inspection engine.
- `cors_tester.py`: Active CORS testing engine.
- `exposure_scanner.py`: Asynchronous exposure scanner with Soft-404 baseline filtering.
- `reporter.py`: JSON, HTML dashboard, and Rich table exporter.
- `config.py`: Centralized wordlists, signatures, and configuration settings.
