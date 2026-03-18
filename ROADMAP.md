<div align="center">

# 🗺️ Phish Extractor — Roadmap

**Planned fixes, enhancements, and future direction**

[![Version 1](https://img.shields.io/badge/version-1.0-blue.svg?logo=github&logoColor=white)]()
[![Version 2](https://img.shields.io/badge/version-2.0-orange.svg?logo=github&logoColor=white)]()
[![Issues](https://img.shields.io/github/issues/gurvinny/Automated-Phish-Extractor)](https://github.com/gurvinny/Automated-Phish-Extractor/issues)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

<p align="center">
  <em>This document tracks what's being fixed in v1 and what's being built in v2.</em>
</p>

---

</div>

## 📌 Version 1.0 — Stabilisation & Hardening

> Version 1 is the current release. The goal of this phase is to fix known bugs, close security gaps, and improve reliability before introducing new features.

---

### 🐛 Bug Fixes

| # | Issue | Description |
|---|-------|-------------|
| [#7](https://github.com/gurvinny/Automated-Phish-Extractor/issues/7) | IPv6 regex misses compressed and mixed-notation addresses | `IPV6_PATTERN` fails to match `2001:db8::1`, `::ffff:192.0.2.1`, and similar compressed forms |
| [#10](https://github.com/gurvinny/Automated-Phish-Extractor/issues/10) | Risk scoring ignores SPF softfail and DMARC quarantine | `calculate_risk()` only counts `fail` — `softfail` and `quarantine` contribute zero to the score |
| [#12](https://github.com/gurvinny/Automated-Phish-Extractor/issues/12) | `--output` path not validated | Format/extension mismatch silently produces garbled output |
| [#16](https://github.com/gurvinny/Automated-Phish-Extractor/issues/16) | False positive domain extraction | File extensions (`.php`, `.html`, `.asp`) matched as domain IOCs |
| [#17](https://github.com/gurvinny/Automated-Phish-Extractor/issues/17) | No IPv6 private/loopback address filtering | Private IPv6 addresses bypass the routable check and reach API enrichment |
| [#18](https://github.com/gurvinny/Automated-Phish-Extractor/issues/18) | Inconsistent email header defanging | `From` is defanged but `To` is not; `defang_domain()` called on full `user@host` strings |
| [#6](https://github.com/gurvinny/Automated-Phish-Extractor/issues/6) | IOC extraction never scans email headers | `Received`, `Reply-To`, and `X-Originating-IP` headers are ignored during IOC extraction |
| [#5](https://github.com/gurvinny/Automated-Phish-Extractor/issues/5) | No rate-limit back-off between API calls | HTTP 429 responses are reported but never retried with exponential back-off |

---

### 🔒 Security

| # | Issue | Description |
|---|-------|-------------|
| [#4](https://github.com/gurvinny/Automated-Phish-Extractor/issues/4) | API keys may leak into DEBUG logs | Keys passed via headers can appear in `requests` debug output written to stderr or syslog |
| [#8](https://github.com/gurvinny/Automated-Phish-Extractor/issues/8) | No file-size limit | Crafted oversized `.eml` files can exhaust memory (DoS vector) |
| [#9](https://github.com/gurvinny/Automated-Phish-Extractor/issues/9) | Attachment filename not sanitised | Raw `Content-Disposition` filename flows unsanitised — path traversal risk |

---

### ✨ Enhancements

| # | Issue | Description |
|---|-------|-------------|
| [#13](https://github.com/gurvinny/Automated-Phish-Extractor/issues/13) | Filter tracking pixels | 1×1 transparent GIF/PNG attachments should be excluded from VT lookups and reports |
| [#14](https://github.com/gurvinny/Automated-Phish-Extractor/issues/14) | Parallelise API enrichment | Replace sequential blocking calls with `ThreadPoolExecutor` to reduce total enrichment time |

---

### 📚 Docs & Testing

| # | Issue | Description |
|---|-------|-------------|
| [#11](https://github.com/gurvinny/Automated-Phish-Extractor/issues/11) | No unit or integration tests | Add a `pytest` suite with mock `.eml` fixtures covering IOC extraction, scoring, and report output |
| [#15](https://github.com/gurvinny/Automated-Phish-Extractor/issues/15) | Add `.env.example` and secrets-management guidance | Document required environment variables and provide a safe template |
| [#19](https://github.com/gurvinny/Automated-Phish-Extractor/issues/19) | Broken LICENSE link in CONTRIBUTING.md | `[MIT License](LICENSE)` → `[MIT License](LICENSE.md)` |

---

## 🚀 Version 2.0 — Campaign Intelligence Platform

> Version 2 is the next major release. The defining upgrade: **v1 analyzes one email, v2 analyzes a campaign.** Every feature below follows from that goal.

---

### 🏗️ Core Architecture

| Feature | Description |
|---------|-------------|
| **Batch mode** | Accept a directory or glob of `.eml` files and produce one combined report across all samples |
| **IOC caching (SQLite)** | Persist enrichment results locally so the same IOC is never queried twice across runs |
| **Async API enrichment** | Replace blocking `requests` calls with `asyncio` + `aiohttp` for 10× faster enrichment |
| **Installable package** | `pyproject.toml` + `pip install phish-extractor` instead of running a raw script |
| **Plugin system** | Drop-in new threat intel sources without modifying core code |

---

### 🧠 Intelligence Upgrades

| Feature | Description |
|---------|-------------|
| **Campaign clustering** | Group related emails by shared IOCs, sending infrastructure, or body patterns across a batch |
| **WHOIS / domain age enrichment** | Flag newly registered domains — one of the strongest phishing signals |
| **Reply-To ≠ From detection** | Automatically flag emails where the reply address differs from the sender |
| **URL unshortening** | Resolve bit.ly, tinyurl, t.co, and other shorteners to their real destinations before analysis |
| **HTML entity & obfuscation decoding** | Decode `&#46;`, base64 blobs, and comment-injected URLs before IOC extraction to defeat evasion |
| **Phishing lure scoring** | Keyword and urgency pattern detection on body text ("verify your account", "urgent action required") |
| **GeoIP enrichment** | Country and ASN data for extracted IPs, surfaced in reports and factored into risk scoring |

---

### 🔗 New Integrations

| Integration | Description |
|------------|-------------|
| **URLhaus** | Free, specialised phishing and malware hosting database — strong complement to VirusTotal |
| **Shodan** | Service enumeration and open-port data for attacker infrastructure |
| **MISP push** | POST extracted IOCs directly to a MISP threat intelligence instance |

---

### 📄 Output & Reporting

| Feature | Description |
|---------|-------------|
| **HTML report** | Styled, self-contained HTML output shareable with stakeholders without a Markdown renderer |
| **STIX 2.1 export** | Industry-standard threat intel format for direct SIEM/SOAR ingest |
| **Webhook / API mode** | Accept `.eml` over HTTP POST and return JSON — enables pipeline and automation integration |

---

### 🛠️ Developer & Ops

| Feature | Description |
|---------|-------------|
| **pytest suite + GitHub Actions CI** | Lint (`ruff`), type-check (`mypy`), and run tests on every PR automatically |
| **Docker image** | Single-command deployment with no Python environment setup required |
| **Pre-commit hooks** | `ruff` + `mypy` checks enforced locally before every commit |

---

## 🗓️ At a Glance

```
v1.0  ████████████░░░░░░  Stabilisation — bugs, security, tests
v2.0  ░░░░░░░░░░░░░░░░░░  Campaign intelligence platform
```

| Milestone | Focus | Status |
|-----------|-------|--------|
| v1.0 | Bug fixes, security hardening, test suite, docs | 🔧 In Progress |
| v2.0 | Batch mode, campaign clustering, new integrations, HTML/STIX output | 📅 Planned |

---

<div align="center">
  <i>Developed with ❤️ by <a href="https://github.com/gurvinny">Gurvin Singh</a></i>
</div>
