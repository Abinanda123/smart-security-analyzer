from bs4 import BeautifulSoup
from pathlib import Path

p = Path("data/raw/cwe/CWE-78-OS-command-injection.html")
soup = BeautifulSoup(p.read_text(encoding="utf-8", errors="ignore"), "html.parser")

for tag in soup(["script", "style", "nav", "header", "footer"]):
    tag.decompose()

# Target key sections defined by MITRE
target_sections = [
    "Description",
    "Extended_Description",
    "Demonstrative_Examples",
    "Potential_Mitigations"
]

for sec in target_sections:
    # Match any div whose id starts with the section name
    div = soup.find("div", id=lambda x: x and x.startswith(sec))
    if div:
        text = " ".join([line.strip() for line in div.get_text().splitlines() if line.strip()])
        print(f"\n=== Found Section: {sec} ===")
        print(f"Content Preview: {text[:160]}...")
    else:
        print(f"\n=== Section Not Found: {sec} ===")