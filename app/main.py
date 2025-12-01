from fastapi import FastAPI
from app.api.routes import router as api_router
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="SAFU or NOT - Link Checker",
    description="A simple service to check whether a link appears safe or suspicious.",
    version="1.0.0"
)

# Register all API routes
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)