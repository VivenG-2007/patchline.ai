from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.rate_limit import limiter
from app.core.security import CurrentUser, require_auth
from app.models.schemas import AnalyzeRequest, ChatRequest, ChatResponse, GenerateRequest
from app.services.ai_service import run_chat

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.post("/chat", response_model=ChatResponse)
@limiter.limit("20/minute")  # AI calls are expensive — tighter than general API limits
async def chat(request: Request, payload: ChatRequest, user: CurrentUser = Depends(require_auth)):
    result = await run_chat(
        owner_id=user.id,
        messages=[m.model_dump() for m in payload.messages],
        model=payload.model,
        conversation_id=payload.conversation_id,
    )
    return result


@router.post("/generate", response_model=ChatResponse)
@limiter.limit("20/minute")
async def generate(request: Request, payload: GenerateRequest, user: CurrentUser = Depends(require_auth)):
    result = await run_chat(
        owner_id=None,
        messages=[{"role": "user", "content": payload.prompt}],
        model=payload.model,
    )
    return result


@router.post("/analyze", response_model=ChatResponse)
@limiter.limit("20/minute")
async def analyze(request: Request, payload: AnalyzeRequest, user: CurrentUser = Depends(require_auth)):
    if not payload.input:
        raise HTTPException(status_code=400, detail='"input" is required')
    messages = [
        {"role": "system", "content": payload.instructions or "Analyze the following input and summarize the key points."},
        {"role": "user", "content": payload.input[:8000]},
    ]
    result = await run_chat(owner_id=user.id, messages=messages, model=payload.model)
    return result
