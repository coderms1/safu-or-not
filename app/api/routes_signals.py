# routes_signals.py
from fastapi import APIRouter, Query
import httpx
import os
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import re

router = APIRouter(prefix="/api", tags=["signals"])

SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_API_KEY")


@router.get("/threat-intel")
async def threat_intel(url: str = Query(...)):
    if not SAFE_BROWSING_KEY:
        return {"hits": [], "clean": True}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "safu-or-not", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"{endpoint}?key={SAFE_BROWSING_KEY}", json=payload
            )
            data = r.json()
            matches = data.get("matches", [])

            hits = [{"source": "Google Safe Browsing", "label": m["threatType"]} for m in matches]
            return {"hits": hits, "clean": not bool(hits)}

    except Exception:
        return {"hits": [], "clean": True}


@router.get("/domain-signals")
async def domain_signals(domain: str = Query(...)):
    age_days = None

    try:
        import whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age_days = (datetime.utcnow() - created).days
    except Exception:
        pass

    ssl_valid = None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            ssl_valid = True
    except Exception:
        ssl_valid = False

    return {
        "domainAgeDays": age_days,
        "https": True,
        "sslValid": ssl_valid,
    }


@router.get("/redirects")
async def redirects(url: str = Query(...)):
    chain = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            r = await client.get(url)
            for h in r.history:
                chain.append(str(h.url))
            chain.append(str(r.url))
    except Exception:
        pass

    return {"count": max(0, len(chain) - 1), "chain": chain}


@router.get("/typo-risk")
async def typo_risk(domain: str = Query(...)):
    suspicious = re.search(r"(wallet|secure|login|claim|verify)", domain)
    if suspicious:
        return {"risk": "medium", "reason": "Suspicious keyword in domain"}

    if "-" in domain or domain.count("l") > 3:
        return {"risk": "low"}

    return {"risk": "low"}


@router.get("/content-scan")
async def content_scan(url: str = Query(...)):
    patterns = [
        "eth_requestAccounts",
        "walletconnect",
        "approve",
        "drain",
        "claim airdrop",
    ]

    matches = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            html = r.text.lower()
            for p in patterns:
                if p in html:
                    matches.append(p)
    except Exception:
        pass

    return {"suspicious": bool(matches), "matches": matches}