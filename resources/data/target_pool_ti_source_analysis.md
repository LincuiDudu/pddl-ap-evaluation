# Target Pool TI Source Analysis

Analysis of threat intelligence (TI) sources used in `target_pool_ti.json` for CVE-to-PDDL attack path generation.

**Dataset:** 26 CVEs (21 Java ecosystem + 4 Claude Code + 1 PHP)

---

## Mandatory Sources

### 1. NVD Description (`description`)

| Item | Detail |
|------|--------|
| **Source** | NIST National Vulnerability Database (NVD) |
| **What it is** | Official vulnerability description published by NVD, typically submitted by CVE Numbering Authorities (CNAs) |
| **Content** | Affected product/version, vulnerability type, impact summary, fix version |
| **Coverage** | 26/26 (100%) |
| **Free access** | Yes. NVD API v2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX` |
| **Trustworthiness** | High. Government-maintained, peer-reviewed, industry standard |
| **Value for AP generation** | **Baseline** -- provides the core vulnerability context (what software, what flaw, what impact). Necessary but often insufficient alone: descriptions are brief and lack exploitation detail |

**Example (CVE-2022-1471):**
> SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization.

---

### 2. CWE Weakness (`cwe`)

| Item | Detail |
|------|--------|
| **Source** | MITRE Common Weakness Enumeration |
| **What it is** | Standardized classification of the software weakness type, including weakness name, description, and common attack patterns |
| **Content** | CWE ID + name + description of the weakness class. Our field includes enriched attack pattern descriptions |
| **Coverage** | 25/26 (96%) -- only CVE-2023-34055 has no CWE |
| **Free access** | Yes. `https://cwe.mitre.org/data/definitions/XXX.html` |
| **Trustworthiness** | High. MITRE-maintained, industry standard taxonomy |
| **Value for AP generation** | **High** -- maps the specific CVE to a general weakness class with known attack patterns. Helps LLM understand *what category of attack* this is and what typical exploitation steps look like. Bridges the gap between CVE-specific description and generalizable attack knowledge |

**Example (CVE-2022-1471):**
> CWE-502: Deserialization of Untrusted Data
> The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid. Deserialization flaws allow an attacker to send crafted input that, when deserialized, results in arbitrary code execution, denial of service, or other malicious outcomes.
> Attack patterns: attacker crafts serialized object with malicious payload -> application deserializes it without type checking -> arbitrary class instantiation -> code execution.

---

### 3. CVSS Vector NL (`cvss_vector_nl`)

| Item | Detail |
|------|--------|
| **Source** | NVD (originally CVSS v3.1 vector from NVD API, converted to natural language) |
| **What it is** | Natural language expansion of the CVSS v3.1 vector string, describing attack characteristics and impact dimensions |
| **Content** | Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact, Base Score and Severity |
| **Coverage** | 26/26 (100%) -- CVE-2024-12798 uses CVSS v4.0 (no v3.1 available) |
| **Free access** | Yes. Derived from NVD API |
| **Trustworthiness** | High. Standardized scoring by NVD analysts |
| **Value for AP generation** | **Medium-High** -- explicitly describes attack preconditions (network access? privileges? user interaction?) and impact scope (CIA triad). Directly informs PDDL preconditions (e.g., `Privileges Required: None` -> attacker needs no prior access) and effects (e.g., `Confidentiality Impact: High` -> data exfiltration is possible) |

**Example (CVE-2022-1471):**
> Attack Vector: Network, Attack Complexity: Low, Privileges Required: None, User Interaction: None, Scope: Unchanged, Confidentiality Impact: High, Integrity Impact: High, Availability Impact: High. Base Score: 9.8 Critical.

---

### 4. Git Patch Diff Header (`patch_diff_header`)

| Item | Detail |
|------|--------|
| **Source** | Official git repositories of affected open-source projects (GitHub, Bitbucket, Apache Gitbox) |
| **What it is** | Summary of the official fix commit: commit hash, subject line, author, and key changed files |
| **Content** | Commit SHA, subject/message, author name, list of modified source files |
| **Coverage** | 19/26 (73%) -- missing for closed-source (Claude Code 4), unpatched (CVE-2025-9930 1), and hard-to-trace (CVE-2022-40150, CVE-2023-33202) |
| **Free access** | Yes. Public git repositories |
| **Trustworthiness** | High. First-party fix from project maintainers |
| **Value for AP generation** | **High** -- reveals the root cause by showing *what code was changed to fix the vulnerability*. Enables reverse reasoning: if the fix adds input validation to `JSONTokener.java`, the vulnerability was lack of input validation in JSON parsing. More precise than NVD description for identifying the exact attack surface |

**Example (CVE-2022-40149):**
> From 395f8625bcf688743872c8e7f59360d372e77811
> Author: Colm O hEigeartaigh (coheigea)
> Subject: Stack Overflow fix on malformed JSON
> Changes to src/main/java/org/codehaus/jettison/json/JSONTokener.java, src/test/java/org/codehaus/jettison/json/JSONObjectTest.java

---

## Optional Sources

### 5. GHSA Advisory (`ghsa_summary` + `ghsa_description`)

| Item | Detail |
|------|--------|
| **Source** | GitHub Security Advisory Database (GHSA) |
| **What it is** | Security advisories published on GitHub, often by maintainers or security researchers. Two fields: one-line summary and detailed description |
| **Content** | Vulnerability summary, affected versions, severity, technical details (often more detailed than NVD), credit to reporters |
| **Coverage** | 26/26 (100%) |
| **Free access** | Yes. GitHub Advisory Database API or web: `https://github.com/advisories/GHSA-XXXX-XXXX-XXXX` |
| **Trustworthiness** | High. Reviewed by GitHub Security team, cross-referenced with NVD |
| **Value for AP generation** | **Medium-High** -- provides additional technical context beyond NVD. Often includes exploitation mechanism details (e.g., "regex validation used \\S+ which failed to account for $IFS"), affected component specifics, and severity context. Complements NVD description with more actionable vulnerability details |

**Example (CVE-2022-1471):**
> **Summary:** SnakeYaml Constructor Deserialization Remote Code Execution
> **Description:** SnakeYaml's Constructor class, which inherits from SafeConstructor, allows any type be deserialized. Types do not have to match the types of properties in the target class. A ConstructorException is thrown, but only after a malicious payload is deserialized. High severity: lack of type checks during deserialization allows remote code execution.

---

### 6. PoC Readme (`poc_readme`)

| Item | Detail |
|------|--------|
| **Source** | Public Proof-of-Concept repositories on GitHub, security research blogs (Flatt Security, xpnsec, Check Point Research, Cymulate) |
| **What it is** | Summary of publicly available exploit demonstrations: what the PoC does, how it works, specific payloads/commands |
| **Content** | Exploit technique description, specific payloads, step-by-step reproduction, tools used |
| **Coverage** | 12/26 (46%) |
| **Free access** | Yes. Public GitHub repos and security blogs |
| **Trustworthiness** | Medium. Community-contributed, quality varies. Some are from reputable security firms, others from individual researchers. Payloads are verified by disclosure |
| **Value for AP generation** | **High** -- most directly useful for attack path generation. Provides concrete exploitation steps that map closely to PDDL actions. Shows the actual attack flow: what the attacker sends, what happens on the target, what the outcome is |

**Example (CVE-2022-1471):**
> A tiny project for generating payloads for the SnakeYAML deserialization gadget. Uses javax.script.ScriptEngineManager with java.net.URLClassLoader to load a malicious JAR from a remote URL. The attacker compiles malicious Java code into yaml-payload.jar and hosts it on a web server, then crafts a YAML payload that triggers class instantiation via SnakeYaml's Constructor.

---

### 7. CAPEC (`capec`)

| Item | Detail |
|------|--------|
| **Source** | MITRE Common Attack Pattern Enumeration and Classification, mapped from CWE |
| **What it is** | Standardized attack pattern descriptions including attack steps, prerequisites, and consequences. Mapped via CWE -> CAPEC relationship |
| **Content** | CAPEC ID + name + attack description + prerequisites + consequences |
| **Coverage** | 23/26 (88%) -- missing for CVE-2023-34055 (no CWE), CVE-2024-34447 (CWE-297, no direct CAPEC), CVE-2024-38820 (CWE-178, no direct CAPEC) |
| **Free access** | Yes. `https://capec.mitre.org/data/definitions/XXX.html` |
| **Trustworthiness** | High. MITRE-maintained, peer-reviewed |
| **Value for AP generation** | **High** -- describes attack patterns in a structured Prerequisites -> Steps -> Consequences format that directly aligns with PDDL preconditions -> actions -> effects. More actionable than CWE (which describes the *weakness*) because CAPEC describes the *attack* |

**Example (CVE-2022-1471, via CWE-502):**
> CAPEC-586 Object Injection: Adversary injects malicious content into serialized objects; when deserialized without validation, attacker achieves unauthorized outcomes including RCE. Prerequisites: application deserializes data before validation. Consequences: resource consumption, data modification, unauthorized command execution.

---

### 8. Exploit-DB (`exploit_db`)

| Item | Detail |
|------|--------|
| **Source** | Exploit Database (exploit-db.com), maintained by OffSec |
| **What it is** | Archive of public exploits and vulnerable software. Entries include EDB-ID, exploit title, platform, and technique description |
| **Content** | EDB-ID, exploit title, brief technique description, platform/type |
| **Coverage** | 2/26 (8%) -- only CVE-2023-44487 (HTTP/2 Rapid Reset) and CVE-2025-24813 (Tomcat RCE) |
| **Free access** | Yes. `https://www.exploit-db.com/` and searchsploit CLI |
| **Trustworthiness** | Medium-High. Curated by OffSec, exploits are tested before inclusion |
| **Value for AP generation** | **Medium** -- provides verified exploit details with specific technique descriptions. However, very low coverage for our dataset (Java library vulnerabilities are underrepresented on Exploit-DB). Overlaps significantly with `poc_readme` when both are present |

**Example (CVE-2025-24813):**
> EDB-52134: Apache Tomcat RCE via partial PUT. Uploads malicious serialized Java object via path equivalence flaw; deserialized when file-based session storage is enabled. Platform: Multiple/Webapps. CVSS 9.8.

---

## Coverage Summary

| # | Source | Field(s) | Tier | Coverage | Free | Trust |
|---|--------|----------|------|----------|------|-------|
| 1 | NVD Description | `description` | Mandatory | 26/26 (100%) | Yes | High |
| 2 | CWE Weakness | `cwe` | Mandatory | 25/26 (96%) | Yes | High |
| 3 | CVSS Vector NL | `cvss_vector_nl` | Mandatory | 26/26 (100%) | Yes | High |
| 4 | Git Patch Diff | `patch_diff_header` | Mandatory | 19/26 (73%) | Yes | High |
| 5 | GHSA Advisory | `ghsa_summary`, `ghsa_description` | Optional | 26/26 (100%) | Yes | High |
| 6 | PoC Repos | `poc_readme` | Optional | 12/26 (46%) | Yes | Medium |
| 7 | CAPEC | `capec` | Optional | 23/26 (88%) | Yes | High |
| 8 | Exploit-DB | `exploit_db` | Optional | 2/26 (8%) | Yes | Medium-High |

## Rejected Sources

| Source | Reason |
|--------|--------|
| OSV Database (Google OSV API) | `affected` and `references` info already covered by NVD description + GHSA; references are URLs not NL content |
| CISA KEV | Only ~1,587 CVEs in catalog globally; very few of our 26 CVEs would match; low incremental value |

## Not Yet Included

| Source | Status |
|--------|--------|
| Vendor Advisory | Listed as optional CTI source but not collected. No unified API; high collection cost, content overlaps with GHSA |
