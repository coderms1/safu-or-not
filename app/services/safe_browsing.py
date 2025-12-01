import httpx
from app.utils.config import SAFE_BROWSING_API_KEY, SAFE_BROWSING_URL, DISCLAIMER
from app.models.schemas import CheckResponse


async def check_url_safety(url: str) -> CheckResponse:
    """
    Calls Google Safe Browsing API and returns a CheckResponse.
    Ensures all returned values are JSON-serializable.
    """

    # ❗ Ensure URL is always string-serializable
    url = str(url).strip()

    payload = {
        "client": {
            "clientId": "safu_or_not",
            "clientVersion": "1.0",
        },
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

    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.post(
            SAFE_BROWSING_URL,
            json=payload,
        )

    if res.status_code != 200:
        raise Exception(f"Safe Browsing API error: {res.text}")

    data = res.json()

    # Google returns {"matches": [...] } ONLY when dangerous
    matches = data.get("matches", [])

    # ---------------------------
    # CASE 1: SAFE
    # ---------------------------
    if not matches:
        return CheckResponse(
            url=url,
            status="safe",
            details="No known threats detected.",
            disclaimer=DISCLAIMER,
        )

    # ---------------------------
    # CASE 2: UNSAFE
    # ---------------------------
    threat_types = sorted({str(m.get("threatType", "UNKNOWN")) for m in matches})

    return CheckResponse(
        url=url,
        status="not_safe",
        details="Unsafe indicators detected: " + ", ".join(threat_types),
        disclaimer=DISCLAIMER,
    )
