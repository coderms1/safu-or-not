# schemas.py
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from pydantic import Field


# LINK CHECKER (legacy support)

class CheckRequest(BaseModel):
    url: HttpUrl


class CheckResponse(BaseModel):
    url: str
    status: str
    details: Optional[str] = None
    domain_age: Optional[str] = None
    ssl_status: Optional[str] = None
    wallet_required: Optional[str] = None
    disclaimer: str


# TOKEN ANALYSIS (new system)

class AnalyzeRequest(BaseModel):
    chain: str = Field(..., examples=["solana", "ethereum", "base"])
    address: str


class TokenInfo(BaseModel):
    chain: str
    address: str
    name: Optional[str] = None
    symbol: Optional[str] = None
    age_minutes: Optional[int] = None


class ScoreBlock(BaseModel):
    risk: int = 50
    rug_probability: int = 50
    liquidity_health: int = 50
    distribution: int = 50


class Signal(BaseModel):
    key: str
    value: Optional[float] = None
    # info | low | medium | high
    severity: str = "info"  
    note: Optional[str] = None


class Sources(BaseModel):
    dexscreener: bool = False
    moralis: bool = False
    goplus: bool = False


class Meta(BaseModel):
    cached: bool = False
    request_id: Optional[str] = None


class AnalyzeResponse(BaseModel):
    token: TokenInfo
    scores: ScoreBlock
    signals: List[Signal] = Field(default_factory=list)
    verdict: str = "UNKNOWN"  # UNKNOWN | SPECULATIVE | ELEVATED | STRUCTURAL_RISK
    sources: Sources = Field(default_factory=Sources)
    meta: Meta = Field(default_factory=Meta)