import os
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

if not SAFE_BROWSING_API_KEY:
    raise RuntimeError("SAFE_BROWSING_API_KEY is missing in environment variables.")

SAFE_BROWSING_URL = (
    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
)

DISCLAIMER = (
    "This result is based on third-party URL checks and is for informational purposes only. "
    "Not financial, legal, or security advice. Always verify independently."
    "#NFA #DYOR"
)