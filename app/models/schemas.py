from pydantic import BaseModel, HttpUrl
from typing import Optional

class CheckRequest(BaseModel):
    url: HttpUrl


class CheckResponse(BaseModel):
    url: str
    status: str          # "safe" or "not_safe"
    details: Optional[str] = None
    disclaimer: str
