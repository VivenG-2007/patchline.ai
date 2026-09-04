from azure.storage.blob.aio import BlobServiceClient, ContainerClient

from app.config import get_settings

_container_client: ContainerClient | None = None


def get_container_client() -> ContainerClient | None:
    global _container_client
    settings = get_settings()
    if not settings.azure_storage_connection_string:
        return None
    if _container_client is None:
        service_client = BlobServiceClient.from_connection_string(settings.azure_storage_connection_string)
        _container_client = service_client.get_container_client(settings.azure_storage_container)
    return _container_client


async def ensure_container() -> None:
    client = get_container_client()
    if client is None:
        return
    if not await client.exists():
        await client.create_container()  # private by default — no public/anonymous access
