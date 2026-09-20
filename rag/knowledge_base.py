import json
from pathlib import Path


KNOWLEDGE_FILE = Path(__file__).parent / "mvp_knowledge_base.json"

def load_documents():
    with KNOWLEDGE_FILE.open(encoding="utf-8") as file:
        documents = json.load(file)

    return documents

def get_words(text):
    return set(text.lower().split())


def search_documents(documents, query):
    query_words = get_words(query)
    results = []

    for document in documents:
        title = document.get("title", "")
        content = document.get("content", "")

        searchable_text = title + " " + content
        document_words = get_words(searchable_text)

        common_words = query_words & document_words
        score = len(common_words)

        if score > 0:
            results.append((score, document))

    results.sort(
        reverse=True,
        key=lambda item: item[0]
    )

    return results[:3]

documents = load_documents()



results = search_documents(
    documents,
    "user input passed to os.system"
)

print("Found",len(results))

for score, document in results:
    print(
        score,
        "-",
        document["title"]
    )

