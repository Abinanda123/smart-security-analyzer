import json
from pathlib import Path
from rag.embeddings import embed_documents

PROJECT_ROOT = Path(__file__).parent.parent
PROCESSED_FILE = PROJECT_ROOT / "data" / "processed" / "security_knowledge.json"
EMBEDDED_FILE = PROJECT_ROOT / "data" / "processed" / "embedded_knowledge.json"


def setup_and_index():
    if not PROCESSED_FILE.exists():
        raise FileNotFoundError(f"Knowledge file missing at: {PROCESSED_FILE}. Run rag/ingestion.py first.")

    with PROCESSED_FILE.open("r", encoding="utf-8") as f:
        chunks = json.load(f)

    print(f"Loaded {len(chunks)} chunks from {PROCESSED_FILE.name}")
    print("Generating local 384-dim embeddings via FastEmbed (ONNX Runtime)...")

    # Extract text content and generate embeddings locally
    texts = [c["content"] for c in chunks]
    vectors = embed_documents(texts)

    # Attach vectors directly to the chunk schema
    embedded_records = []
    for chunk, vector in zip(chunks, vectors):
        embedded_records.append({
            "id": chunk["id"],
            "cwe_id": chunk.get("cwe_id", "UNKNOWN"),
            "source": chunk.get("source", ""),
            "vulnerability_type": chunk.get("vulnerability_type", ""),
            "section_title": chunk.get("section_title", ""),
            "pattern_type": chunk.get("pattern_type", "concept"),
            "content": chunk.get("content", ""),
            "vector": vector,
        })

    # Save complete index to disk (typically <200 KB)
    with EMBEDDED_FILE.open("w", encoding="utf-8") as f:
        json.dump(embedded_records, f, indent=2, ensure_ascii=False)

    print(f"Index built! Saved {len(embedded_records)} indexed vectors to: {EMBEDDED_FILE}")


if __name__ == "__main__":
    setup_and_index()