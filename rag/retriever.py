import json
import math
from pathlib import Path
from rag.embeddings import embed_query

PROJECT_ROOT = Path(__file__).parent.parent
EMBEDDED_FILE = PROJECT_ROOT / "data" / "processed" / "embedded_knowledge.json"

_INDEX_CACHE: list[dict] | None = None


def _load_index() -> list[dict]:
    global _INDEX_CACHE
    if _INDEX_CACHE is None:
        if not EMBEDDED_FILE.exists():
            raise FileNotFoundError(
                f"Missing index at {EMBEDDED_FILE}. Run 'python -m rag.vector_store' first."
            )
        with EMBEDDED_FILE.open("r", encoding="utf-8") as f:
            _INDEX_CACHE = json.load(f)
    return _INDEX_CACHE


def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def retrieve_security_context(finding: dict, top_k: int = 3) -> list[dict]:
    """
    Given an AST finding dict, applies strict CWE metadata filtering
    and retrieves top matching remediation/vulnerability patterns.
    """
    records = _load_index()
    cwe_id = finding.get("cwe_id")

    # Filter candidates by target CWE
    candidates = [r for r in records if r["cwe_id"] == cwe_id] if cwe_id else records
    if not candidates:
        candidates = records

    # Embed finding query text locally
    query_text = f"{finding.get('sink', '')} {finding.get('code', '')}".strip()
    query_vector = embed_query(query_text)

    # Compute similarity scores
    scored = []
    for r in candidates:
        sim = _cosine_similarity(query_vector, r["vector"])
        scored.append((sim, r))

    scored.sort(key=lambda x: x[0], reverse=True)

    results = []
    for score, r in scored[:top_k]:
        results.append({
            "score": round(score, 4),
            "cwe_id": r["cwe_id"],
            "source": r["source"],
            "section_title": r["section_title"],
            "pattern_type": r["pattern_type"],
            "content": r["content"],
        })
    return results


if __name__ == "__main__":
    # Test 1: Command Injection (CWE-78)
    test_cmd = {
        "cwe_id": "CWE-78",
        "sink": "subprocess.Popen",
        "code": "subprocess.Popen(cmd, shell=False)",
    }
    print(f"\n--- Testing Query 1: {test_cmd['sink']} ({test_cmd['cwe_id']}) ---")
    for i, m in enumerate(retrieve_security_context(test_cmd, top_k=2), 1):
        print(f"[{i}] {m['source']} | Score: {m['score']} | {m['section_title']}")

    # Test 2: SQL Injection (CWE-89)
    test_sql = {
        "cwe_id": "CWE-89",
        "sink": "cursor.execute",
        "code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    }
    print(f"\n--- Testing Query 2: {test_sql['sink']} ({test_sql['cwe_id']}) ---")
    for i, m in enumerate(retrieve_security_context(test_sql, top_k=2), 1):
        print(f"[{i}] {m['source']} | Score: {m['score']} | {m['section_title']}")