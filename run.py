"""
Master Entry Point for CyberShield AI Application.
Launches the FastAPI backend and serves the interactive Web Dashboard.
"""
import sys
import uvicorn
from backend.config import settings

def main():
    print("=" * 70)
    print(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    print("AI-Based Cyber Threat Prediction System for Digital Banking Security")
    print(f"Environment: {settings.ENVIRONMENT} | Host: {settings.HOST}:{settings.PORT}")
    print("=" * 70)
    print(f"Web Dashboard: http://localhost:{settings.PORT}")
    print(f"API Documentation (Swagger): http://localhost:{settings.PORT}/docs")
    print(f"API Health Check: http://localhost:{settings.PORT}/api/v1/health")
    print("=" * 70)
    
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info"
    )

if __name__ == "__main__":
    main()
