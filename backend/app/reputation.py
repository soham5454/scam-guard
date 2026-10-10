"""Optional URL reputation lookup via VirusTotal (needs VT_API_KEY in .env)."""
from __future__ import annotations

import base64
import json
import os
import urllib.request


def virustotal_malicious_count(url: str, timeout: float = 4.0) -> int | None:
    """Return how many engines flag `url` as malicious, or None if unavailable."""
    key = os.getenv("VT_API_KEY")
    if not key:
        return None
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": key},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.load(response)
        return int(data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0))
    except Exception:
        return None  # network error, unknown URL, quota exceeded, etc.
