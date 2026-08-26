<div align="center">

# 🎣 Phish Extractor

**Automated IOC Extraction & Threat Intelligence Reporter**

[![CI](https://img.shields.io/github/actions/workflow/status/gurvinny/Automated-Phish-Extractor/pytest.yml?branch=main&style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/gurvinny/Automated-Phish-Extractor/actions/workflows/pytest.yml)
[![Tests](https://img.shields.io/badge/tests-pytest-2ea043?style=for-the-badge&logo=pytest&logoColor=white)](https://github.com/gurvinny/Automated-Phish-Extractor/actions/workflows/pytest.yml)
[![Python](https://img.shields.io/badge/python-3.10_--_3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)](LICENSE.md)
[![Version](https://img.shields.io/badge/version-1.0--beta-blue?style=for-the-badge&logo=github&logoColor=white)](ROADMAP.md)
[![Roadmap](https://img.shields.io/badge/roadmap-v2.0_planned-orange?style=for-the-badge)](ROADMAP.md)

<p align="center">
  <em>Reducing SOC alert fatigue by automating the ingestion, parsing, and enrichment of malicious .eml files.</em>
</p>

---

</div>

## 📖 Description

A major challenge for Tier 1 SOC analysts is the sheer volume of repetitive tasks, which frequently leads to **alert fatigue**. **Phish Extractor** is a Python-based automation tool that addresses this by:
1. Ingesting raw `.eml` phishing reports.
2. Extracting critical **Indicators of Compromise (IOCs)**.
3. Enriching them with threat intelligence from **VirusTotal** and **AbuseIPDB**.
4. Generating human-readable **Markdown** or structured **JSON** reports.

By fully automating the manual labor of parsing headers, calculating file hashes, defanging links, and querying APIs, analysts can focus their time on triage, containment, and higher-value incident response tasks.

---

## ✨ Features

- 🔍 **Header Parsing:** Extracts sender, recipient, subject, dates and — most importantly — `SPF`, `DKIM` and `DMARC` results. Malformed headers are tolerated rather than fatal; see [Handling hostile input](#-handling-hostile-input).
- 🧬 **IOC Extraction:** Pulls URLs, domains, IPv4/IPv6 addresses and `SHA-256` hashes for every attachment, walking the full MIME tree. Only **sender-controlled** headers are scanned, so your own mail relays and recipient domains are never extracted or submitted to third-party APIs.
- 🕵️ **Identity-Mismatch Detection:** Compares the `From` domain against `Reply-To` and the envelope sender. This is what catches **business email compromise**, which carries no URL, no attachment and no malicious infrastructure for a reputation feed to score. Comparison is on the registrable domain, so ordinary bounce subdomains do not false-positive.
- 🛡️ **Defanging:** Rewrites URLs, IPs and domains (`hxxps://evil[.]com`) so indicators can be shared without accidental execution. Attacker-controlled text is also escaped so it cannot render as a live link inside the report itself.
- 🧠 **Threat Intel Enrichment:** Queries **VirusTotal v3** and **AbuseIPDB**, with retry backoff, a shared rate-limit budget, and non-routable addresses filtered out before any request is made.
- 📊 **Risk Scoring:** Derives `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` from authentication results, identity mismatches and confirmed-malicious hits. Unresolved lookups contribute a **capped** amount, so a missing API key or an exhausted quota cannot inflate every message to `CRITICAL`. An indicator VirusTotal has simply never seen is reported as *unknown* rather than as an error — a newly registered phishing domain is always unknown, and penalising it for being new would work against the tool.

---

## 🛠️ Prerequisites & Installation

* **Python**: `3.10` – `3.13` (all four are covered by CI)
* **OS**: Cross-platform (Windows, macOS, Linux)

For Windows/VS Code users, follow these commands to set up the environment:

**1. Clone the repository:**
```powershell
git clone https://github.com/gurvinny/Automated-Phish-Extractor.git
cd Automated-Phish-Extractor
```

**2. Create and activate a virtual environment:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**3. Install the dependencies:**
```powershell
pip install -r requirements.txt
```

**4. Configure your API keys & environment settings:**
Copy the example environment file and fill in your keys:
```powershell
copy .env.example .env
```

Available environment settings in `.env`:
- `VT_API_KEY`: Your VirusTotal v3 API key.
- `ABUSEIPDB_API_KEY`: Your AbuseIPDB API key.
- `MAX_EML_SIZE_MB`: Maximum permitted `.eml` file size in MB (default: `25`).
- `MIN_ATTACHMENT_BYTES`: Minimum attachment size threshold in bytes (default: `256`).

> ⚠️ **Never commit your `.env` file.** It is listed in `.gitignore` to prevent accidental exposure.
> If you accidentally push secrets, **rotate your API keys immediately** via the VirusTotal and AbuseIPDB dashboards — treat any exposed key as compromised.

---

## 🔒 Secrets Management

- `.env` is excluded from version control via `.gitignore` — never remove this rule.
- In CI/CD pipelines, use **GitHub Actions Secrets** (or your vault of choice) instead of `.env` files.
- To proactively prevent secret leaks, consider adding a `pre-commit` hook using [`detect-secrets`](https://github.com/Yelp/detect-secrets) or [`gitleaks`](https://github.com/gitleaks/gitleaks):
```bash
pip install detect-secrets
detect-secrets scan > .secrets.baseline
```

- If you ever accidentally commit a real API key, rotate it immediately — assume it is compromised.

---

## 🚀 Usage

Run the tool against any raw `.eml` file to parse and generate a threat report.

### Standard Run
To perform a full analysis with external threat intelligence queries:
```powershell
python phish_extractor.py samples/malicious/credential-phish.eml -o report.md
```
*This extracts all IOCs, performs lookups against VirusTotal and AbuseIPDB, and outputs a formatted Markdown report.*

### Offline Mode (`--skip-intel`)
If you want to extract IOCs and defang them **without** sending anything to external APIs (useful for highly confidential investigations or OPSEC reasons):
```powershell
python phish_extractor.py samples/malicious/bec-wire-transfer.eml --skip-intel
```

**To see all available CLI options:**
```powershell
python phish_extractor.py --help
```

---

## 🧪 Sample Corpus

Eight synthetic messages ship with the tool, in [`samples/`](samples/) — three
malicious, three clean, two deliberately malformed. Every address, domain and IP
comes from ranges reserved for documentation, so nothing points at real
infrastructure. Full breakdown in [`samples/README.md`](samples/README.md).

```powershell
python phish_extractor.py samples/clean/newsletter-legitimate.eml --skip-intel
python phish_extractor.py samples/malicious/bec-wire-transfer.eml --skip-intel
```

| Corpus | Expected outcome |
|---|---|
| `clean/` | `LOW`, zero identity mismatches — these exist to catch **false positives**, the failure mode that actually erodes trust in a triage tool |
| `malicious/` | `HIGH` or `CRITICAL` |
| `edge/` | Must not crash |

The test suite asserts each of those, so a regression in scoring or parsing
fails CI rather than reaching an analyst.

> **Why the samples show no IP indicators:** documentation IP ranges are not
> globally routable, and the tool filters non-routable addresses so private and
> reserved hops are never sent to a reputation API. That is the filter working.
> Real captures surface IP IOCs normally.

---

## 🛡️ Handling Hostile Input

Every input to this tool is attacker-controlled by definition, so a malformed
message is treated as a defect to survive, not as bad input to reject:

- **Malformed headers** — a bare `From: broken@` raises `IndexError` inside
  Python's own header parser. Header reads fall back to the raw value.
- **Bogus charsets** — a part declaring `charset="not-a-real-codec"` raises
  `LookupError` from the codec lookup. Decoding falls back to UTF-8 with
  replacement, which is lossy but keeps hostnames and URLs intact.
- **Path traversal** — an attachment named `../../etc/passwd` is reduced to a
  bare filename before it is ever displayed or written.
- **Bidi overrides** — `invoice<U+202E>cod.scr` displays to an analyst as
  though it ends in `.doc`. Bidirectional control characters are stripped.
- **Report injection** — attacker text in a subject or filename cannot render
  as a live link, break out of a code span, or shift a table column.

Both crash cases above were found by the `edge/` samples and are covered by
regression tests.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed |
| `2` | Input error — file missing, unreadable, oversized, or not a file |
| `3` | Unexpected failure |

---

## 🔬 Running the Test Suite

The default suite is fully offline — no network, no keys, no quota:

```powershell
python -m unittest discover -s tests
```

### Live API tests (opt-in)

A second suite exercises the real VirusTotal and AbuseIPDB endpoints. It is
gated behind **two** conditions: keys configured **and** an explicit opt-in.

```powershell
$env:RUN_LIVE_API_TESTS=1
python -m unittest tests.test_live_api -v
```

Both gates exist deliberately. Someone with working keys in `.env` running the
default suite should not silently make outbound requests or spend quota —
opting in has to be an act.

These cover the one thing a mock cannot: that provider **response schemas still
match what the parser expects**. A mock encodes our assumption; only a live call
tests the provider's reality. They deliberately do *not* assert specific
verdicts, because reputation data changes and a suite that fails when an
unrelated domain's score moves is a suite people learn to ignore.

> **Do not add these keys to GitHub Actions.** CI stays offline and mocked:
> live calls are rate-limited, non-deterministic, and would put credentials in
> the automation of a public repository for no testing benefit.

---

## 🎯 Detection Engineering

To effectively bridge the gap between reactive analysis and proactive defense, the `detections/` folder is included in this repository. It contains actionable detection rules formulated off of the artifacts parsed by `phish_extractor.py`:

- 🟡 **`yara_rule.yar`** — hunts the SHA-256 and base64 payload of the attachment in `samples/malicious/credential-phish.eml`.
- 🟠 **`sigma_rule.yml`** — email-gateway logs where DMARC fails and the subject carries a known lure.
- 🔴 **`sigma_bec_reply_to_mismatch.yml`** — mail whose `Reply-To` domain differs from the `From` domain, so a reply leaves the organisation the message claims to be from. This is the detection equivalent of the identity-mismatch check above, and the one that covers BEC, where there is no infrastructure to look up.

All three parse cleanly as YAML/YARA and are validated in CI.

---

---

## 🗺️ Roadmap

This project follows a versioned roadmap. See [ROADMAP.md](ROADMAP.md) for the full breakdown.

### 🔧 Version 1.0 Beta — Stabilisation & Hardening *(current)*
Focused on fixing known bugs, closing security gaps, and building a test suite before adding new features.

| Category | Highlights |
|----------|------------|
| 🐛 Bug Fixes | IPv6 regex, false positive IOC extraction, inconsistent defanging, risk scoring gaps |
| 🔒 Security | API key leak prevention, file-size limits, attachment filename sanitisation |
| ✨ Enhancements | Tracking pixel filtering, parallelised API enrichment |
| 📚 Docs & Testing | pytest suite, `.env.example`, secrets-management guidance |

### 🚀 Version 2.0 — Campaign Intelligence Platform *(planned)*
The defining upgrade: **v1 analyzes one email, v2 analyzes a campaign.**

| Category | Highlights |
|----------|------------|
| 🏗️ Architecture | Batch mode, async enrichment, IOC caching, installable package |
| 🧠 Intelligence | Campaign clustering, WHOIS/domain age, URL unshortening, phishing lure scoring |
| 🔗 Integrations | URLhaus, Shodan, MISP push, Webhook/API mode |
| 📄 Output | HTML reports, STIX 2.1 export, GitHub Actions CI, Docker image |

➡️ [View the full roadmap →](ROADMAP.md)

---

<div align="center">
  <i>Built by <a href="https://github.com/gurvinny">@gurvinny</a></i>
</div>
