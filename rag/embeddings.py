import os

import voyageai
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VOYAGE_API_KEY")

client = voyageai.Client(api_key=api_key)

def embed_query(text):
    result = client.embed(
        texts=[text],
        model="voyage-4",
        input_type="query",
    )

    return result.embeddings[0]

def embed_documents(texts):
    result = client.embed(
        texts=texts,
        model="voyage-4",
        input_type="document",
    )

    return result.embeddings[0]