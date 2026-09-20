# Raw security-source manifest

**Retrieval date:** 2026-09-18  
**Scope:** Raw reference material for OS Command Injection (CWE-78), SQL Injection (CWE-89), and Code Injection (CWE-94). No embeddings were generated and no data was uploaded to Pinecone.

| Source | Authoritative URLs retrieved | Retrieval date | License / provenance | File count | Purpose |
| --- | --- | --- | --- | ---: | --- |
| MITRE CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | 2026-09-18 | Official MITRE CWE web pages. Use is governed by the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html). | 3 | Canonical weakness definitions, relationships, mitigations, examples, and detection guidance. |
| OWASP Cheat Sheet Series | [OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) | 2026-09-18 | Official OWASP Cheat Sheet Series pages, licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). | 3 | Practical prevention guidance for command, SQL, and general/code injection contexts. |
| PyCQA Bandit | [B602](https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html), [B608](https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html), [B102](https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html) | 2026-09-18 | Official PyCQA Bandit documentation. The Bandit project is distributed under the [Apache License 2.0](https://github.com/PyCQA/bandit/blob/main/LICENSE). | 3 | Python static-analysis checks corresponding to shell command execution, SQL expressions, and `exec` use. |
| NIST National Vulnerability Database (NVD) | [CWE-78 query](https://services.nvd.nist.gov/rest/json/cves/2.0/?cweId=CWE-78&resultsPerPage=5), [CWE-89 query](https://services.nvd.nist.gov/rest/json/cves/2.0/?cweId=CWE-89&resultsPerPage=5), [CWE-94 query](https://services.nvd.nist.gov/rest/json/cves/2.0/?cweId=CWE-94&resultsPerPage=5) | 2026-09-18 | Official NIST NVD CVE API responses; see [NVD data/terms](https://nvd.nist.gov/general/terms-of-use). The saved collection is intentionally limited to five returned CVEs per CWE, not the complete NVD database. | 3 | Focused, machine-readable CVE examples mapped by the NVD API to each requested CWE. |

## Saved files

- `cwe/`: `CWE-78-OS-command-injection.html`, `CWE-89-SQL-injection.html`, `CWE-94-code-injection.html`
- `owasp/`: `OS_Command_Injection_Defense_Cheat_Sheet.html`, `SQL_Injection_Prevention_Cheat_Sheet.html`, `Injection_Prevention_Cheat_Sheet.html`
- `bandit/`: `B602-subprocess-popen-shell-true.html`, `B608-hardcoded-SQL-expressions.html`, `B102-exec-used.html`
- `nvd/`: `CWE-78-selected-CVEs.json`, `CWE-89-selected-CVEs.json`, `CWE-94-selected-CVEs.json`

## NVD selection record

The API's five returned records were retained per query to keep the corpus deliberately small. At retrieval, the saved CVEs were:

| CWE | CVE IDs retained |
| --- | --- |
| CWE-78 | CVE-1999-0067, CVE-2001-1583, CVE-2002-0061, CVE-2002-1660, CVE-2002-1898 |
| CWE-89 | CVE-2002-0999, CVE-2002-2252, CVE-2002-2277, CVE-2002-2304, CVE-2002-2305 |
| CWE-94 | CVE-1999-0509, CVE-1999-0491, CVE-1999-0891, CVE-1999-0702, CVE-2000-0155 |

## Verification record

All 12 downloaded files were checked after retrieval: every HTML response contains an HTML document marker; each NVD JSON response parses successfully and contains five CVE records; each file is non-empty. SHA-256 hashes were computed during verification and can be regenerated with `Get-FileHash -Algorithm SHA256`.
