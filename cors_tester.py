"""
Active CORS (Cross-Origin Resource Sharing) misconfiguration testing engine.
Sends crafted Origin payloads to evaluate insecure reflection, wildcards with credentials, and null origin trust.
"""

import asyncio
from typing import Dict, List, Any
import httpx
from config import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW


class CorsTester:
    """Performs active CORS probing against a target URL."""

    def __init__(self, client: httpx.AsyncClient, target_url: str):
        self.client = client
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []

    async def test_cors(self) -> List[Dict[str, Any]]:
        """Execute active CORS tests with crafted Origin headers."""
        test_origins = [
            ("https://evil.com", "Arbitrary External Domain"),
            ("null", "Null Origin (`null`)"),
            ("https://allowed-prefix.evil.com", "Prefix Domain Bypass"),
            ("https://evil.com.allowed-suffix.com", "Suffix Domain Bypass"),
            (f"{self.target_url}.evil.com", "Target Subdomain Pre-pend Bypass")
        ]

        # First, test with wildcard or standard arbitrary origin
        for origin, desc in test_origins:
            try:
                headers = {"Origin": origin}
                response = await self.client.options(self.target_url, headers=headers, follow_redirects=True)
                # If OPTIONS returns 404/405, fallback to GET with Origin header
                if response.status_code in [404, 405, 403]:
                    response = await self.client.get(self.target_url, headers=headers, follow_redirects=True)

                acao = response.headers.get("access-control-allow-origin")
                acac = response.headers.get("access-control-allow-credentials", "").lower()

                if acao:
                    self._evaluate_cors_response(origin, desc, acao, acac)

            except Exception:
                # Target might not respond or block request
                continue

        # Check explicit wildcard "*" response without custom origin
        try:
            response = await self.client.get(self.target_url, follow_redirects=True)
            acao = response.headers.get("access-control-allow-origin")
            acac = response.headers.get("access-control-allow-credentials", "").lower()
            if acao == "*":
                if acac == "true":
                    self.findings.append({
                        "category": "CORS Misconfiguration",
                        "header": "Access-Control-Allow-Origin",
                        "severity": SEVERITY_HIGH,
                        "title": "CORS Wildcard with Credentials Enabled",
                        "description": "The server returns `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`. This is a critical misconfiguration allowing any website to read authenticated user data.",
                        "recommendation": "Never combine wildcard origins with credentials. Specify trusted explicit origins.",
                        "current_value": f"ACAO: *, ACAC: {acac}"
                    })
                else:
                    self.findings.append({
                        "category": "CORS Misconfiguration",
                        "header": "Access-Control-Allow-Origin",
                        "severity": SEVERITY_LOW,
                        "title": "CORS Wildcard (*) Enabled",
                        "description": "The server allows any origin (`*`) to access resources via CORS.",
                        "recommendation": "Restrict Access-Control-Allow-Origin to trusted domains if the endpoint serves sensitive data.",
                        "current_value": "i*"
                    })
        except Exception:
            pass

        return self.findings

    def _evaluate_cors_response(self, tested_origin: str, test_desc: str, acao: str, acac: str) -> None:
        """Evaluate whether the returned CORS headers represent a vulnerability."""
        is_credentials_enabled = (acac == "true")

        # 1. Arbitrary Origin Reflection
        if acao.lower() == tested_origin.lower() or acao == "*":
            if is_credentials_enabled:
                severity = SEVERITY_HIGH
                title = f"CORS Arbitrary Origin Reflection with Credentials ({test_desc})"
                desc = (
                    f"The server reflects the untrusted Origin ('{tested_origin}') in `Access-Control-Allow-Origin` "
                    f"and sets `Access-Control-Allow-Credentials: true`. An attacker can steal sensitive data from authenticated users."
                )
            else:
                severity = SEVERITY_MEDIUM
                title = f"CORS Arbitrary Origin Reflection ({test_desc})"
                desc = (
                    f"The server dynamically reflects the untrusted Origin ('{tested_origin}') in `Access-Control-Allow-Origin`."
                )

            # Avoid duplicate findings for the same type
            existing_titles = [f["title"] for f in self.findings]
            if title not in existing_titles:
                self.findings.append({
                    "category": "CORS Misconfiguration",
                    "header": "Access-Control-Allow-Origin",
                    "severity": severity,
                    "title": title,
                    "description": desc,
                    "recommendation": "Implement an explicit whitelist of trusted origins instead of dynamic reflection or regex parsing.",
                    "current_value": f"ACAO: {acao}, ACAC: {acac or 'false'}"
                })
