from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str = Field(min_length=1, max_length=8000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1)
    model: Optional[str] = None
    conversation_id: Optional[str] = None


class GenerateRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)
    model: Optional[str] = None


class AnalyzeRequest(BaseModel):
    input: str = Field(min_length=1, max_length=8000)
    instructions: Optional[str] = None
    model: Optional[str] = None


class ChatResponse(BaseModel):
    content: str
    usage: dict[str, Any] = {}
    cached: bool = False


class FileAssetOut(BaseModel):
    id: str
    owner_id: str
    blob_name: str
    original_name: str
    mime_type: str
    size_bytes: int
    container: str
    metadata: dict[str, Any] = {}
    created_at: datetime
