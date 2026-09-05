import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

from app.core import memory_store, chroma_client
from azure.storage.blob.aio import BlobServiceClient

async def verify_all():
    print("==================================================")
    print("1. VERIFYING CHROMADB RAG WORKFLOW")
    print("==================================================")
    
    col = await chroma_client.get_collection()
    count = await asyncio.to_thread(col.count)
    print(f"Total documents currently in Chroma Cloud: {count}")
    
    test_finding = {
        "id": "probe-sql-finding",
        "title": "SQL Injection in User Login Query",
        "category": "injection",
        "severity": "high",
        "description": "User input concatenated directly into database query string.",
        "file": "services/auth-service/src/routes/auth.js"
    }
    
    print("\nExecuting semantic RAG search for SQL injection finding...")
    results = await memory_store.retrieve_similar(owner_id="", finding=test_finding, top_k=3)
    print(f"Retrieved {len(results)} relevant prior fixes from ChromaDB:")
    for idx, item in enumerate(results, 1):
        print(f"  [{idx}] Title: {item.get('title')}")
        print(f"      Similarity: {item.get('similarity')*100:.1f}%")
        print(f"      Source: {item.get('source')}")
        print(f"      Verified: {item.get('verified')}")
        print(f"      Fix Summary: {item.get('fixSummary')}")
        print()

    print("==================================================")
    print("2. VERIFYING AZURE BLOB STORAGE UPLOAD WORKFLOW")
    print("==================================================")
    conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    container_name = os.getenv("AZURE_STORAGE_CONTAINER")
    
    blob_service = BlobServiceClient.from_connection_string(conn_str)
    container = blob_service.get_container_client(container_name)
    
    exists = await container.exists()
    print(f"Azure Blob Container '{container_name}' exists: {exists}")
    
    probe_name = "test-workflow/scan-report-probe.json"
    blob = container.get_blob_client(probe_name)
    await blob.upload_blob(b'{"status": "verified", "engine": "rag-pipeline"}', overwrite=True)
    print(f"Successfully uploaded scan report to blob: {probe_name}")
    
    downloaded = await (await blob.download_blob()).readall()
    print(f"Successfully downloaded back from blob: {downloaded.decode('utf-8')}")
    
    await blob.delete_blob()
    print(f"Successfully cleaned up probe blob: {probe_name}")
    await blob_service.close()
    
    print("\nALL WORKFLOWS (RAG & UPLOADING) VERIFIED AND WORKING 100%!")

if __name__ == "__main__":
    asyncio.run(verify_all())
