"""
HTTP Security Headers inspection engine.
Evaluates missing headers, insecure directives, and information disclosure banners.
"""

from typing import Dict, List, Any
from config import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


class HeadersAuditor:
    """Audits HTTP response headers for security best practices and misconfigurations."""

    def __init__(self, headers: Dict[str, str], url: str):
        # Normalize header keys to lowercase for robust case-insensitive lookup
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.url = url
        self.findings: List[Dict[str, Any]] = []

    def audit(self) -> List[Dict[str, Any]]:
        """Run all security header checks."""
        self._check_content_security_policy()
        self._check_strict_transport_security()
        self._check_x_frame_options()
        self._check_x_content_type_options()
        self._check_referrer_policy()
        self._check_permissions_policy()
        self._check_information_disclosure()
        return self.findings

    def _add_finding(
        self,
        header_name: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        current_value: str = None
    ) -> None:
        self.findings.append({
            "category": "HTTP Security Headers",
            "header": header_name,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "current_value": current_value or "Missing"
        })

    def _check_content_security_policy(self) -> None:
        csp = self.headers.get("content-security-policy")
        if not csp:
            self._add_finding(
                header_name="Content-Security-Policy",
                severity=SEVERITY_MEDIUM,
                title="Missing Content-Security-Policy (CSP)",
                description="The Content-Security-Policy header is missing. CSP helps prevent Cross-Site Scripting (XSS), data injection attacks, and clickjacking.",
                recommendation="Implement a robust CSP header (e.g., `default-src 'self'; script-src 'self'`)."
            )
        else:
            csp_lower = csp.lower()
            if "unsafe-inline" in csp_lower:
                self._add_finding(
                    header_name="Content-Security-Policy",
                    severity=SEVERITY_MEDIUM,
                    title="CSP Contains 'unsafe-inline'",
                    description="The Content-Security-Policy header allows 'unsafe-inline' scripts or styles, which weakens protection against XSS.",
                    recommendation="Remove 'unsafe-inline' and use nonces, hashes, or external script files.",
                    current_value=csp
                )
            if "unsafe-eval" in csp_lower:
                self._add_finding(
                    header_name="Content-Security-Policy",
                    severity=SEVERITY_MEDIUM,
                    title="CSP Contains 'unsafe-eval'",
                    description="The Content-Security-Policy header allows 'unsafe-eval', permitting the execution of string-to-code evaluation functions like eval().",
                    recommendation="Remove 'unsafe-eval' from your CSP directives.",
                    current_value=csp
                )
            if "*" in csp_lower and not "default-src 'self'" in csp_lower:
                # General check for overly permissive wildcards
                pass

    def _check_strict_transport_security(self) -> None:
        hsts = self.headers.get("strict-transport-security")
        if not hsts:
            # Only flag HSTS as Medium if target is HTTPS, or note it
            if self.url.startswith("https://"):
                self._add_finding(
                    header_name="Strict-Transport-Security",
                    severity=SEVERITY_MEDIUM,
                    title="Missing HTTP Strict-Transport-Security (HSTS)",
                    description="The HSTS header is missing on an HTTPS site. This leaves visitors vulnerable to SSL stripping downgrade attacks.",
                    recommendation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                )
        else:
            hsts_lower = hsts.lower()
            # Check max-age threshold (recommend >= 6 months / 15768000 seconds)
            if "max-age=" in hsts_lower:
                try:
                    parts = [p.strip() for p in hsts_lower.split(";")]
                    max_age_val = 0
                    for part in parts:
                        if part.startswith("max-age="):
                            max_age_val = int(part.split("=")[1])
                    if max_age_val < 15768000:
                        self._add_finding(
                            header_name="Strict-Transport-Security",
                            severity=SEVERITY_LOW,
                            title="HSTS max-age is too short",
                            description=f"HSTS max-age is set to {max_age_val} seconds, which is less than the recommended 6 months (15768000 seconds).",
                            recommendation="Increase max-age to at least 31536000 (1 year).",
                            current_value=hsts
                        )
                except (ValueError, IndexError):
                    pass
            if "includesubdomains" not in hsts_lower:
                self._add_finding(
                    header_name="Strict-Transport-Security",
                    severity=SEVERITY_LOW,
                    title="HSTS missing includeSubDomains directive",
                    description="The HSTS policy does not include subdomains, leaving subdomains vulnerable to insecure HTTP connections.",
                    recommendation="Add `includeSubDomains` to your HSTS header.",
                    current_value=hsts
                )

    def _check_x_frame_options(self) -> None:
        xfo = self.headers.get("x-frame-options")
        if not xfo:
            self._add_finding(
                header_name="X-Frame-Options",
                severity=SEVERITY_LOW,
                title="Missing X-Frame-Options Header",
                description="The X-Frame-Options header is missing, which can expose the website to clickjacking attacks via malicious iframes.",
                recommendation="Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`."
            )
        else:
            xfo_upper = xfo.upper().strip()
            if xfo_upper not in ["DENY", "SAMEORIGIN"]:
                self._add_finding(
                    header_name="X-Frame-Options",
                    severity=SEVERITY_LOW,
                    title="Weak X-Frame-Options Directive",
                    description=f"X-Frame-Options is set to an unrecognized or weak value: {xfo}",
                    recommendation="Use `DENY` or `SAMEORIGIN`.",
                    current_value=xfo
                )

    def _check_x_content_type_options(self) -> None:
        xcto = self.headers.get("x-content-type-options")
        if not xcto or xcto.lower().strip() != "nosniff":
            self._add_finding(
                header_name="X-Content-Type-Options",
                severity=SEVERITY_LOW,
                title="Missing or Misconfigured X-Content-Type-Options Header",
                description="The X-Content-Type-Options header is missing or not set to 'nosniff'. This can lead to MIME-sniffing vulnerabilities.",
                recommendation="Set `X-Content-Type-Options: nosniff`.",
                current_value=xcto
            )

    def _check_referrer_policy(self) -> None:
        rp = self.headers.get("referrer-policy")
        insecure_policies = [
            "unsafe-url",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin"
        ]
        if not rp:
            self._add_finding(
                header_name="Referrer-Policy",
                severity=SEVERITY_LOW,
                title="Missing Referrer-Policy Header",
                description="The Referrer-Policy header is missing, potentially leaking sensitive URL paths in the Referer header to external sites.",
                recommendation="Implement a secure Referrer-Policy such as `strict-origin-when-cross-origin` or `no-referrer`."
            )
        elif rp.lower().strip() in insecure_policies:
            self._add_finding(
                header_name="Referrer-Policy",
                severity=SEVERITY_LOW,
                title="Insecure Referrer-Policy Directive",
                description=f"Referrer-Policy is set to '{rp}', which may leak sensitive query parameters or URL structure.",
                recommendation="Use `strict-origin-when-cross-origin` or `no-referrer`.",
                current_value=rp
            )

    def _check_permissions_policy(self) -> None:
        pp = self.headers.get("permissions-policy") or self.headers.get("feature-policy")
        if not pp:
            self._add_finding(
                header_name="Permissions-Policy",
                severity=SEVERITY_INFO,
                title="Missing Permissions-Policy Header",
                description="The Permissions-Policy header is missing. This header restricts browser features (like camera, microphone, geolocation) available to the site and embedded frames.",
                recommendation="Implement a Permissions-Policy header restricting unused browser APIs (e.g., `camera=(), microphone=()`)."
            )

    def _check_information_disclosure(self) -> None:
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
        for header in disclosure_headers:
            val = self.headers.get(header)
            if val:
                self._add_finding(
                    header_name=header.title(),
                    severity=SEVERITY_INFO,
                    title=f"Information Disclosure: {header.title()} Header",
                    description=f"The '{header}' header discloses software version information ({val}), which can assist attackers in targeting known vulnerabilities.",
                    recommendation=f"Remove or obfuscate the '{header}' header in server configuration.",
                    current_value=val
                )
