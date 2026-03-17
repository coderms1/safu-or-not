#main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.api.routes_ai import router as ai_router

app = FastAPI(
    title="SAFU or NOT - Link Checker",
    description="A simple service to check whether a link appears safe or suspicious.",
    version="1.0.0"
)

origins = [
    "*",
    "https://safuornot.com",
    "https://www.safuornot.com",
    "http://safuornot.com",
    "http://www.safuornot.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ai_router)