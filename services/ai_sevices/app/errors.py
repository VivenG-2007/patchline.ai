import uuid

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.core.logging import get_logger

logger = get_logger()


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    request_id = _request_id(request)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.detail, "code": "HTTP_ERROR", "requestId": request_id}},
        headers={"x-request-id": request_id},
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = _request_id(request)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": {
                "message": "Validation failed",
                "code": "VALIDATION_ERROR",
                "details": exc.errors(),
                "requestId": request_id,
            }
        },
        headers={"x-request-id": request_id},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id(request)
    settings = get_settings()
    logger.error("unhandled_exception", error=str(exc), path=request.url.path, request_id=request_id)
    message = "Internal server error" if settings.environment == "production" else str(exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": {"message": message, "code": "INTERNAL_ERROR", "requestId": request_id}},
        headers={"x-request-id": request_id},
    )
