from app.config import get_settings
from app.services.ai_providers import azure_openai, featherless, groq, mock, openai as openai_provider

# Every provider module exports the same shape: async def chat(messages, model) -> dict(content, usage).
# Add a new file here + one entry below to plug in RAG, embeddings, vision, or speech providers later.
_PROVIDERS = {
    "mock": mock,
    "groq": groq,
    "openai": openai_provider,
    "azure_openai": azure_openai,
    "featherless": featherless,
}


def get_provider():
    settings = get_settings()
    return get_provider_by_name(settings.ai_provider)


def get_provider_by_name(name: str):
    """Look up a provider module by name directly, bypassing settings.ai_provider
    — used by app/services/model_router.py to reach "featherless" specifically
    regardless of what AI_PROVIDER is set to (AI_PROVIDER is the fallback/manual
    override provider, not the primary-routing switch once Featherless is
    configured)."""
    provider = _PROVIDERS.get(name)
    if provider is None:
        raise ValueError(f"Unknown AI provider '{name}'. Supported: {', '.join(_PROVIDERS)}")
    return provider
