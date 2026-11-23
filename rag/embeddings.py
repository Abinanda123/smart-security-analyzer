from fastembed import TextEmbedding

# Loads BAAI/bge-small-en-v1.5 (384 dimensions, runs locally via ONNX Runtime on CPU)
embedding_model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")


def embed_query(text: str) -> list[float]:
    """Generates an embedding vector for a single query."""
    embeddings = list(embedding_model.embed([text]))
    return embeddings[0].tolist()


def embed_documents(texts: list[str]) -> list[list[float]]:
    """Generates embeddings for a batch of documents locally with zero API limits."""
    embeddings = list(embedding_model.embed(texts))
    return [e.tolist() for e in embeddings]


if __name__ == "__main__":
    print("Testing local FastEmbed model...")
    test_vec = embed_query("subprocess.Popen shell=False")
    print(f"Success! Vector dimension: {len(test_vec)}")