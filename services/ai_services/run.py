"""
Local entrypoint. In production use the Dockerfile's uvicorn/gunicorn command
instead (multiple workers) — this is for `python run.py` during development.
"""
import uvicorn

from app.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=settings.environment != "production")
