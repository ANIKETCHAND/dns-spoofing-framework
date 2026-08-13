"""
Main FastAPI application for DNS Spoofing Simulation Framework.
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.api import routes
from app.database.database import init_database
from app.config import settings
from app.utils.logger import get_logger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting DNS Spoofing Simulation Framework...")
    init_database()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down DNS Spoofing Simulation Framework...")


# Create FastAPI app
app = FastAPI(
    title="DNS Spoofing Simulation Framework",
    description="Educational framework for DNS spoofing detection and visualization",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(routes.router, prefix="/api")

# Mount static files & templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "frontend", "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# HTML Page Routes
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Render the dashboard UI."""
    return templates.TemplateResponse(request=request, name="index.html", context={"page": "dashboard"})


@app.get("/events", response_class=HTMLResponse)
async def serve_events_page(request: Request):
    """Render the DNS events list UI."""
    return templates.TemplateResponse(request=request, name="events.html", context={"page": "events"})


@app.get("/alerts", response_class=HTMLResponse)
async def serve_alerts_page(request: Request):
    """Render alerts view."""
    return templates.TemplateResponse(request=request, name="index.html", context={"page": "alerts"})


@app.get("/pcap", response_class=HTMLResponse)
async def serve_pcap_page(request: Request):
    """Render PCAP analysis view."""
    return templates.TemplateResponse(request=request, name="index.html", context={"page": "pcap"})


@app.get("/settings", response_class=HTMLResponse)
async def serve_settings_page(request: Request):
    """Render settings view."""
    return templates.TemplateResponse(request=request, name="index.html", context={"page": "settings"})


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": "2026-08-12T00:00:00Z"}


if __name__ == "__main__":
    import uvicorn
    settings.print_config()
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )