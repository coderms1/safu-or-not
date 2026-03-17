# app/utils/config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Optional: URL safety / Safe Browsing
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

SAFE_BROWSING_URL = (
    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    if SAFE_BROWSING_API_KEY
    else None
)

DISCLAIMER = (
    "This result is based on third-party checks and is for informational purposes only. "
    "Not financial, legal, or security advice. Always verify independently."
)