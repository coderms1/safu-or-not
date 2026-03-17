# safu_worker.py
import asyncio
from app.safu_x import run_x_bot
from app.safu_tg import run_tg_bot

async def main():
    await asyncio.gather(
        run_x_bot(),
        run_tg_bot()
    )

if __name__ == "__main__":
    asyncio.run(main())