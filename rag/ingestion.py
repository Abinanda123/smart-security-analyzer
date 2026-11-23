import json
import re
from pathlib import Path
from bs4 import BeautifulSoup

# ==================================================
# 1. Project Directory Paths
# ==================================================
PROJECT_ROOT = Path(__file__).parent.parent

CWE_DIR = PROJECT_ROOT / "data" / "raw" / "cwe"
OWASP_DIR = PROJECT_ROOT / "data" / "raw" / "owasp"
BANDIT_DIR = PROJECT_ROOT / "data" / "raw" / "bandit"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

PROCESSED_FILE = PROCESSED_DIR / "security_knowledge.json"

# ==================================================
# 2. Metadata Mappings
# ==================================================
CWE_METADATA = {
    "CWE-78": {"vulnerability_type": "OS Command Injection"},
    "CWE-89": {"vulnerability_type": "SQL Injection"},
    "CWE-94": {"vulnerability_type": "Code Injection"},
}

OWASP_METADATA = {
    "Injection_Prevention_Cheat_Sheet": {
        "cwe_id": "CWE-78",
        "vulnerability_type": "Injection",
    },
    "OS_Command_Injection_Defense_Cheat_Sheet": {
        "cwe_id": "CWE-78",
        "vulnerability_type": "OS Command Injection",
    },
    "SQL_Injection_Prevention_Cheat_Sheet": {
        "cwe_id": "CWE-89",
        "vulnerability_type": "SQL Injection",
    },
}

BANDIT_METADATA = {
    "B102": {
        "cwe_id": "CWE-94",
        "vulnerability_type": "Code Injection",
        "title": "Bandit B102: Test for the use of exec",
    },
    "B602": {
        "cwe_id": "CWE-78",
        "vulnerability_type": "OS Command Injection",
        "title": "Bandit B602: Test for use of popen with shell equals true",
    },
    "B605": {
        "cwe_id": "CWE-78",
        "vulnerability_type": "OS Command Injection",
        "title": "Bandit B605: Test for starting a process with a shell",
    },
    "B608": {
        "cwe_id": "CWE-89",
        "vulnerability_type": "SQL Injection",
        "title": "Bandit B608: Test for SQL injection",
    },
}

# ==================================================
# 3. Text Cleaning & Classification Helpers
# ==================================================
def clean_text(text: str) -> str:
    """Removes extra whitespace and flattens multiline text."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " ".join(lines)

def classify_pattern(title: str, text: str) -> str:
    """Classifies a section as remediation, vulnerable_pattern, or general concept."""
    combined = f"{title} {text}".lower()
    if any(keyword in combined for keyword in ["defense", "prevention", "remediation", "correct usage", "safe"]):
        return "remediation"
    if any(keyword in combined for keyword in ["incorrect usage", "vulnerable", "attack", "exploit", "issue:"]):
        return "vulnerable_pattern"
    return "concept"


IGNORE_HEADINGS = {
    "edit custom filter",
    "content history",
    "submission history",
    "modification history",
    "previous entry names",
    "references",
}

def extract_sections(soup: BeautifulSoup) -> list[dict]:
    """
    Extracts text grouped by heading tags (h2/h3) rather than arbitrary word counts.
    Filters out navigation forms, buttons, and revision tables.
    """
    for tag in soup(["script", "style", "nav", "header", "footer", "form"]):
        tag.decompose()

    sections = []
    headers = soup.find_all(["h2", "h3"])

    if not headers:
        text = clean_text(soup.get_text(" ", strip=True))
        if text:
            doc_title = soup.title.get_text(strip=True) if soup.title else "Overview"
            sections.append({"title": doc_title, "content": text})
        return sections

    for header in headers:
        raw_title = clean_text(header.get_text(strip=True))
        # Remove anchor symbol ¶ that MkDocs places in headings
        title = raw_title.replace("¶", "").strip()

        # Skip UI noise and revision history sections
        if title.lower() in IGNORE_HEADINGS:
            continue

        body_parts = []
        for sibling in header.find_next_siblings():
            if sibling.name in ["h2", "h3"]:
                break
            text = clean_text(sibling.get_text(" ", strip=True))
            if text:
                body_parts.append(text)

        content = " ".join(body_parts)
        if len(content) > 50:  # Skip tiny fragments
            sections.append({"title": title, "content": content})

    return sections

# ==================================================
# 4. Parsers for Raw HTML Sources
# ==================================================
CWE_SECTIONS = [
    "Description",
    "Extended_Description",
    "Demonstrative_Examples",
    "Potential_Mitigations",
]

def parse_cwe_file(file_path: Path) -> list[dict]:
    """Parses key MITRE CWE sections using target div IDs."""
    cwe_id = f"{file_path.stem.split('-')[0]}-{file_path.stem.split('-')[1]}"
    meta = CWE_METADATA.get(cwe_id, {})

    with file_path.open(encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    for tag in soup(["script", "style", "nav", "header", "footer", "form"]):
        tag.decompose()

    doc_title = soup.title.get_text(" ", strip=True) if soup.title else cwe_id

    chunks = []
    for sec_name in CWE_SECTIONS:
        # Match any div whose id starts with the section name
        div = soup.find("div", id=lambda x: x and x.startswith(sec_name))
        if div:
            sec_text = clean_text(div.get_text(" ", strip=True))
            if len(sec_text) > 40:
                chunks.append({
                    "id": f"{cwe_id.lower()}-{sec_name.lower()}",
                    "source": "MITRE CWE",
                    "document_id": cwe_id,
                    "cwe_id": cwe_id,
                    "vulnerability_type": meta.get("vulnerability_type", "Unknown"),
                    "section_title": sec_name.replace("_", " "),
                    "pattern_type": classify_pattern(sec_name, sec_text),
                    "content": f"{clean_text(doc_title)} - {sec_name.replace('_', ' ')}: {sec_text}"
                })
    return chunks

def parse_owasp_file(file_path: Path) -> list[dict]:
    """Parses OWASP Cheat Sheet HTML pages into section chunks."""
    owasp_id = file_path.stem
    meta = OWASP_METADATA.get(owasp_id, {})

    with file_path.open(encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    doc_title = clean_text(soup.title.get_text(strip=True)) if soup.title else owasp_id
    sections = extract_sections(soup)

    chunks = []
    for idx, sec in enumerate(sections):
        chunks.append({
            "id": f"{owasp_id.lower()[:20]}-section-{idx}",
            "source": "OWASP",
            "document_id": owasp_id,
            "cwe_id": meta.get("cwe_id"),
            "vulnerability_type": meta.get("vulnerability_type", "Injection"),
            "section_title": sec["title"],
            "pattern_type": classify_pattern(sec["title"], sec["content"]),
            "content": f"{doc_title} - {sec['title']}: {sec['content']}"
        })
    return chunks

def parse_bandit_file(file_path: Path) -> list[dict]:
    """Parses PyCQA Bandit HTML documentation into structured chunks."""
    rule_id = file_path.stem.split("-")[0].upper()
    meta = BANDIT_METADATA.get(rule_id, {})

    with file_path.open(encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    for tag in soup(["script", "style", "nav", "header", "footer"]):
        tag.decompose()

    full_text = clean_text(soup.get_text(" ", strip=True))

    return [{
        "id": f"{rule_id.lower()}-section-0",
        "source": "PyCQA Bandit",
        "document_id": rule_id,
        "cwe_id": meta.get("cwe_id"),
        "vulnerability_type": meta.get("vulnerability_type", "Python Security"),
        "section_title": meta.get("title", rule_id),
        "pattern_type": "remediation",
        "content": f"{meta.get('title', rule_id)}: {full_text}"
    }]

# ==================================================
# 5. Pipeline Execution
# ==================================================
def main():
    all_chunks = []

    # Ingest MITRE CWE files
    cwe_files = list(CWE_DIR.glob("*.html"))
    for file_path in cwe_files:
        all_chunks.extend(parse_cwe_file(file_path))

    # Ingest OWASP Cheat Sheets
    owasp_files = list(OWASP_DIR.glob("*.html"))
    for file_path in owasp_files:
        all_chunks.extend(parse_owasp_file(file_path))

    # Ingest PyCQA Bandit Documentation
    bandit_files = list(BANDIT_DIR.glob("*.html"))
    for file_path in bandit_files:
        all_chunks.extend(parse_bandit_file(file_path))

    print(f"Total CWE files processed: {len(cwe_files)}")
    print(f"Total OWASP files processed: {len(owasp_files)}")
    print(f"Total Bandit files processed: {len(bandit_files)}")
    print(f"Total structured knowledge chunks created: {len(all_chunks)}")

    if all_chunks:
        print("\n--- Sample Knowledge Chunk Preview ---")
        print(json.dumps(all_chunks[0], indent=2))

    # Write output to processed file
    with PROCESSED_FILE.open("w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2, ensure_ascii=False)

    print(f"\nSaved structured knowledge base to: {PROCESSED_FILE}")

if __name__ == "__main__":
    main()