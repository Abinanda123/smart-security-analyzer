from pathlib import Path

from bs4 import BeautifulSoup


# --------------------------------------------------
# Paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
CWE_DIR = PROJECT_ROOT / "data" / "raw" / "cwe"

CWE_METADATA = {
    "CWE-78": {
        "vulnerability_type": "OS Command Injection"
    },
    "CWE-89": {
        "vulnerability_type": "SQL Injection"
    },
    "CWE-94": {
        "vulnerability_type": "Code Injection"
    }
}

# --------------------------------------------------
# get CWE ID from file path
# --------------------------------------------------

def get_cwe_id(file_path):
    parts = file_path.stem.split("-")

    return f"{parts[0]}-{parts[1]}"


# --------------------------------------------------
# Text cleaning
# --------------------------------------------------


def clean_text(text):
    lines = text.splitlines()

    cleaned_lines = []

    for line in lines:
        line = line.strip()

        if line:
            cleaned_lines.append(line)

    return " ".join(cleaned_lines)


# --------------------------------------------------
# CWE parser
# --------------------------------------------------

def parse_cwe_file(file_path):
    # Read HTML
    with file_path.open(
        encoding="utf-8",
        errors="ignore"
    ) as file:
        html = file.read()

    # Parse HTML
    soup = BeautifulSoup(html, "html.parser")

    # Remove obvious website noise
    for tag in soup([
        "script",
        "style",
        "nav",
        "header",
        "footer"
    ]):
        tag.decompose()

    # -----------------------------
    # Extract title
    # -----------------------------

    raw_title = soup.title.get_text(
        " ",
        strip=True
    )

    title = clean_text(raw_title)

    # -----------------------------
    # Extract full page text
    # -----------------------------

    raw_content = soup.get_text(
        "\n",
        strip=True
    )

    full_content = clean_text(raw_content)

    # -----------------------------
    # Find useful CWE content
    # -----------------------------

    start = full_content.find("Description")

    end = full_content.find("Content History")

    # Some CWE pages may not contain
    # the exact "Content History" text
    if end == -1:
        end = full_content.find("Previous Entry Names")

    # If Description was found
    if start != -1:

        # If an ending marker was also found
        if end != -1 and end > start:
            content = full_content[start:end]

        # Otherwise keep everything after Description
        else:
            content = full_content[start:]

    # Fallback if Description was not found
    else:
        content = full_content

    cwe_id = get_cwe_id(file_path)

    metadata = CWE_METADATA.get(cwe_id, {})

    vulnerability_type = metadata.get(
        "vulnerability_type",
        "Unknown"
        )


    return {
        "source": "CWE",
        "cwe_id": cwe_id,
        "vulnerability_type": vulnerability_type,
        "title": title,
        "content": content
    }


# --------------------------------------------------
# Chunking
# --------------------------------------------------

def chunk_text(text, chunk_size=500, overlap=100):
    words = text.split()

    chunks = []

    start = 0

    while start < len(words):
        end = start + chunk_size

        chunk_words = words[start:end]

        chunk = " ".join(chunk_words)

        chunks.append(chunk)

        start += chunk_size - overlap

    return chunks

def create_chunks(document):
    text_chunks = chunk_text(document["content"])


# --------------------------------------------------
# Load all CWE documents
# --------------------------------------------------

cwe_documents = []

for file_path in CWE_DIR.glob("*.html"):
    document = parse_cwe_file(file_path)

    cwe_documents.append(document)


# --------------------------------------------------
# Test 
# --------------------------------------------------

print("Total CWE documents:", len(cwe_documents))


for document in cwe_documents:

    chunks = chunk_text(
        document["content"]
    )

    print("\n-----------------------------")

    print("Title:")
    print(document["title"])

    print("Content length:")
    print(len(document["content"]))

    print("Chunks:")
    print(len(chunks))

    print("\nFirst 500 characters:")
    print(document["content"][:500])

    print("\nLast 500 characters:")
    print(document["content"][-500:])