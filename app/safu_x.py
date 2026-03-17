# safu_x.py
import os
import httpx
import asyncio
from app.safu_ai import safu_ai_answer

BEARER = os.getenv("X_BEARER_TOKEN")
API_KEY = os.getenv("X_API_KEY")
API_SECRET = os.getenv("X_API_SECRET")
ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN")
ACCESS_SECRET = os.getenv("X_ACCESS_SECRET")

BASE_URL = "https://api.twitter.com/2"


async def post_tweet(text: str):
    url = f"{BASE_URL}/tweets"
    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=20) as client:
        payload = {"text": text}
        r = await client.post(url, headers=headers, json=payload)
        return r.json()


async def reply_to_tweet(text: str, tweet_id: str):
    url = f"{BASE_URL}/tweets"
    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json"
    }

    payload = {
        "text": text,
        "reply": {"in_reply_to_tweet_id": tweet_id}
    }

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(url, headers=headers, json=payload)
        return r.json()


async def fetch_mentions():
    url = f"{BASE_URL}/users/me/mentions"
    headers = {"Authorization": f"Bearer {BEARER}"}

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(url, headers=headers)
        data = r.json()
        return data.get("data", [])


async def run_x_bot():
    seen = set()

    while True:
        try:
            mentions = await fetch_mentions()

            for m in mentions:
                tid = m["id"]
                text = m["text"]

                if tid in seen:
                    continue
                seen.add(tid)

                answer = await safu_ai_answer(text)
                await reply_to_tweet(answer, tid)

        except Exception:
            pass

        await asyncio.sleep(15)