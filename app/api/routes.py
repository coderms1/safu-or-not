from fastapi import APIRouter, HTTPException
from app.models.schemas import CheckRequest, CheckResponse
from app.services.safe_browsing import check_url_safety

router = APIRouter()

@router.post("/check", response_model=CheckResponse)
async def check_link(payload: CheckRequest):
    try:
        response = await check_url_safety(payload.url)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
