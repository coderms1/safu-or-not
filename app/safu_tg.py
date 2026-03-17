# safu_tg.py
import os
import asyncio
from telegram.ext import ApplicationBuilder, MessageHandler, filters
from app.safu_ai import safu_ai_answer

TG_TOKEN = os.getenv("TG_BOT_TOKEN")


async def handle_message(update, context):
    user_text = update.message.text
    reply = await safu_ai_answer(user_text)
    await update.message.reply_text(reply)


async def run_tg_bot():
    app = ApplicationBuilder().token(TG_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    await app.run_polling()