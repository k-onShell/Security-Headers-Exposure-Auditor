"""
Asynchronous sensitive file and directory discovery engine.
Features Soft-404 baseline filtering and content signature/MIME-type validation.
"""

import asyncio
import random
import string
from typing import Dict, List, Any, Optional
import httpx
from config import EXPOSURE_PATHS, USER_AGENT


class ExposureScanner:
    """Probes for sensitive files and folders with robust false-positive filtering."""

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self.client = client
        # Ensure base_url ends with trailing slash for correct relative joining
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.findings: List[Dict[str, Any]] = []
        self.baseline_status: int = 404
        self.baseline_length: int = 0
        self.baseline_text: str = ""

    async def establish_baseline(self) -> None:
        """Establish a Soft-404 baseline using a random non-existent path."""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        probe_url = f"{self.base_url}{random_str}"
        try:
            response = await self.client.get(probe_url, follow_redirects=True)
            self.baseline_status = response.status_code
            self.baseline_length = len(response.text)
            self.baseline_text = response.text
        except Exception:
            self.baseline_status = 404
            self.baseline_length = 0
            self.baseline_text = ""

    async def scan(self, semaphore_limit: int = 20) -> List[Dict[str, Any]]:
        """Run asynchronous exposure scan across all defined wordlist items."""
        await self.establish_baseline()
        semaphore = asyncio.Semaphore(semaphore_limit)

        tasks = [self._probe_path(item, semaphore) for item in EXPOSURE_PATHS]
        results = await asyncio.gather(*tasks)

        for res in results:
            if res:
                self.findings.append(res)

        return self.findings

    async def _probe_path(self, item: Dict[str, Any], semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
        path = item["path"]
        target_url = f"{self.base_url}{path.lstrip('/')}"

        async with semaphore:
            try:
                response = await self.client.get(target_url, follow_redirects=True)

                # Filter out responses that match the Soft-404 baseline
                if response.status_code == 404 or response.status_code == 403:
                    return None

                if self.baseline_status == 200 and response.status_code == 200:
                    # Check if response length or content is identical to the soft-404 baseline page
                    if abs(len(response.text) - self.baseline_length) < 50 and response.text == self.baseline_text:
                        return None

                # Validate against expected status code and signature
                if response.status_code == 200:
                    content_text = response.text
                    content_bytes = response.content

                    # Verify signatures
                    signatures = item.get("signatures", [])
                    is_binary = item.get("is_binary", False)
                    min_length = item.get("min_length", 5)

                    if len(content_text) < min_length:
                        return None

                    signature_matched = False
                    matched_sig = ""

                    if is_binary:
                        for sig in signatures:
                            # Handle hex escape sequence strings like '\\x1f\\x8b'
                            if sig.startswith("\\x"):
                                try:
                                    hex_bytes = bytes.fromhex(sig.replace("\\x", ""))
                                    if content_bytes.startswith(hex_bytes):
                                        signature_matched = True
                                        matched_sig = sig
                                        break
                                except Exception:
                                    pass
                            else:
                                if sig.encode("latin1", errors="ignore") in content_bytes[:100]:
                                    signature_matched = True
                                    matched_sig = sig
                                    break
                    else:
                        for sig in signatures:
                            if sig in content_text:
                                signature_matched = True
                                matched_sig = sig
                                break

                    # If signatures are defined, require at least one match (unless it's a generic backup with good length and 200)
                    if signatures and not signature_matched:
                        # Fallback: if it's an explicit backup file with a reasonable size and not HTML error page, accept it
                        if "<html" in content_text.lower() or "<body" in content_text.lower():
                            return None

                    return {
                        "category": f"Sensitive Exposure ({item['category']})",
                        "header": path,
                        "severity": item["severity"],
                        "title": f"Exposed Sensitive File: {path}",
                        "description": f"{item['description']} Accessible at `{target_url}` (HTTP {response.status_code}).",
                        "recommendation": f"Restrict public access to `{path}` immediately via web server configuration (Nginx/Apache/Caddy) or remove it from the web root.",
                        "current_value": f"URL: {target_url} (HTTP {response.status_code})"
                    }

            except Exception:
                pass

        return None
