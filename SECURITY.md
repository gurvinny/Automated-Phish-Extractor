<div align="center">

# 🔒 Security Policy

**Phish Extractor — Responsible Disclosure & Threat Modeling**

[![Security Policy](https://img.shields.io/badge/Security-Enabled-brightgreen.svg?logo=github&logoColor=white)]()
[![Python Supported](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Vulnerability Reporting](https://img.shields.io/badge/Reporting-Private-red.svg)](mailto:gurvin240@gmail.com)

<p align="center">
  Maintaining a secure environment for automated threat intelligence and SOC operations.
</p>

---

</div>

## 📅 Supported Versions

The following versions of **Phish Extractor** receive security updates. As this is a portfolio project, we focus on the latest stable release.

| Version | Supported          | Python Version | Status                     |
| ------- | ------------------ | -------------- | -------------------------- |
| `1.0.x` | :white_check_mark: | `3.10+`        | Active Maintenance         |
| `< 1.0` | :x:                | N/A            | Unsupported Legacy         |

---

## 🚨 Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.** If you discover a security bug (e.g., a way to bypass defanging, a credential leak risk, or a code execution flaw), please follow our **Responsible Disclosure** process:

1. **Email directly:** Send a detailed report to **gurvin240@gmail.com**.
2. **Include Details:** Provide a summary, steps to reproduce, and the potential impact.
3. **Response:** I (@gurvinny) will acknowledge your report within 48 hours and coordinate a fix.

For general security *improvements* (like adding a new security feature), please follow the [CONTRIBUTING.md](CONTRIBUTING.md) process by opening an enhancement issue.

---

## 🥷 Threat Model & Operational Guidelines

### ⚠️ Execution Context (Principle of Least Privilege)
This script parses untrusted `.eml` files and performs network I/O. **Never run this tool as `Administrator` or `root`.**
* **Best Practice:** Run in a dedicated virtual environment (`venv`) as a standard user.
* **Isolation:** For high-stakes investigations, run the tool within a dedicated analysis VM or container to limit the potential "blast radius."

### 🔑 Secret Management & Contribution
We utilize a `.env` system for API keys. 
* **Contributors:** Ensure `.env` is listed in your `.gitignore` before pushing code. 
* **Reviewers:** Every Pull Request is screened for "secret leakage" using manual review and (ideally) automated hooks. 
* **Leaked Keys:** If a key is accidentally committed, **rotate it immediately.**

### 📡 Operational Security (OPSEC)
Querying external APIs (VirusTotal, AbuseIPDB) alerts third parties that an IOC is being investigated. 
* **Beaconing Risk:** Attackers may monitor these services to see if their infrastructure has been "burned."
* **Stealth Mode:** For sensitive investigations where OPSEC is critical, always use the `--skip-intel` flag.

---

<div align="center">
  <i>Security is a shared responsibility. Thank you for helping keep Phish Extractor safe.</i>
</div>
