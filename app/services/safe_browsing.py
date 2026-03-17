# app/services/safe_browsing.py
import datetime
import ssl
import socket

import httpx
import whois

from app.utils.config import SAFE_BROWSING_URL, DISCLAIMER
from app.models.schemas import CheckResponse


async def detect_wallet_requirement(url: str) -> str:
    keywords = [
        "connect wallet", "walletconnect", "metamask", "window.ethereum",
        "solana.connect", "window.solana", "phantom", "keplr", "tronlink",
        "wallet-adapter",
    ]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            html = resp.text.lower()

        for k in keywords:
            if k in html:
                return "yes"
        return "no"
    except Exception:
        return "unknown"


async def get_domain_age(url: str) -> str:
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return "Unknown"
        age_days = (datetime.datetime.utcnow() - created).days
        return f"{age_days} days"
    except Exception:
        return "Unknown"


async def get_ssl_expiry(url: str) -> str:
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        exp_str = cert.get("notAfter")
        if not exp_str:
            return "Unknown"

        exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (exp - datetime.datetime.utcnow()).days
        return f"Valid (expires in {days_left} days)"
    except Exception:
        return "Unknown"


async def check_url_safety(url: str) -> CheckResponse:
    url = str(url).strip()

    payload = {
        "client": {"clientId": "safu_or_not", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    # Optional: if SAFE_BROWSING_URL isn't configured, we just return "no hits"
    matches = []
    if SAFE_BROWSING_URL:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                res = await client.post(SAFE_BROWSING_URL, json=payload)
            if res.status_code == 200:
                data = res.json()
                matches = data.get("matches", [])
        except Exception:
            matches = []

    domain_age = await get_domain_age(url)
    ssl_status = await get_ssl_expiry(url)
    wallet_flag = await detect_wallet_requirement(url)

    if not matches:
        return CheckResponse(
            url=url,
            status="safe",
            details="No known threats detected.",
            domain_age=domain_age,
            ssl_status=ssl_status,
            wallet_required=wallet_flag,
            disclaimer=DISCLAIMER,
        )

    threat_types = sorted({str(m.get("threatType", "UNKNOWN")) for m in matches})

    return CheckResponse(
        url=url,
        status="not_safe",
        details="Unsafe indicators detected: " + ", ".join(threat_types),
        domain_age=domain_age,
        ssl_status=ssl_status,
        wallet_required=wallet_flag,
        disclaimer=DISCLAIMER,
    )