#safu_ai.py
import os
import httpx

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

system_prompt = (
    "You are SAFU AI, a strict crypto safety expert. "
    "You do not give financial advice. "
    "You analyze URLs, tokens, wallets, contracts, phishing patterns, "
    "and suspicious online behavior. "
    "You explain risks in simple terms. "
    "You never encourage trading or investing. "
    "You warn the user when something feels unsafe. "
    "Keep responses short, clear, and focused only on safety."
)

async def safu_ai_answer(user_input: str) -> str:
    if not OPENAI_API_KEY:
        return "SAFU AI is offline. Missing API key."

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": "gpt-4.1-mini",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_input}
                    ],
                    "max_tokens": 300
                }
            )

        data = r.json()
        return data["choices"][0]["message"]["content"]

    except Exception:
        return "SAFU AI could not process the request."
