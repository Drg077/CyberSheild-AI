"""
FastAPI Application Entry Point.
Initializes routes, middleware, database tables, and static frontend assets.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from backend.config import settings
from database.db_session import engine, Base
from backend.api.routes_health import router as health_router
from backend.api.routes_url import router as url_router
from backend.api.routes_file import router as file_router
from backend.api.routes_history import router as history_router

# Ensure tables are created
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-driven threat detection for digital banking security using explainable ML."
)

# CORS Configuration for Dashboard and Browser Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health_router)
app.include_router(url_router)
app.include_router(file_router)
app.include_router(history_router)

# Mount frontend static directory
frontend_path = settings.BASE_DIR / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler to avoid leaking internal stack traces."""
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred during security processing."}
    )

@app.get("/")
@app.get("/dashboard")
def serve_dashboard():
    index_file = frontend_path / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/api/v1/health"
    }
