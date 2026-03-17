from fastapi import APIRouter
from pydantic import BaseModel
from app.safu_ai import safu_ai_answer

router = APIRouter()

class AskRequest(BaseModel):
    question: str

@router.post("/ask")
async def ask_safu(request: AskRequest):
    answer = await safu_ai_answer(request.question)
    return {"answer": answer}