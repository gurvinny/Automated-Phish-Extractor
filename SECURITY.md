<div align="center">

# 🔒 Security Policy

**Phish Extractor — Responsible Disclosure & Threat Modeling**

[![Security Policy](https://img.shields.io/badge/Security-Enabled-brightgreen.svg?logo=github&logoColor=white)]()
[![Python Supported](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Bug Bounty](https://img.shields.io/badge/Bounty-None_Yet-lightgrey.svg)]()

</div>

---

## 📅 Supported Versions

The following versions of the **Phish Extractor** tool are currently supported with security updates. We rely on the core language features introduced in Python `3.10+`, and no earlier versions are supported.

| Version | Supported          | Python Version Required | Notes                      |
| ------- | ------------------ | ----------------------- | -------------------------- |
| `1.0.x` | :white_check_mark: | `3.10+`                 | Maintained                 |
| `< 1.0` | :x:                | N/A                     | Unsupported legacy code    |

---

## 🚨 Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead, contact me directly via email at:
📧 **gurvin240@gmail.com**

Or, you can reach out via my GitHub profile:
🌐 **[https://github.com/gurvinny](https://github.com/gurvinny)**

I will do my best to acknowledge the vulnerability and respond as soon as possible.

---

## 🥷 Threat Model

To ensure this tool is deployed and utilized securely within SOC environments, please observe the following threat models and operational guidelines:

### ⚠️ Execution Context
This script interacts directly with external files (`.eml`, `.msg`, etc.) and performs network operations. Under no circumstances should this tool be run as an `Administrator`, `Root`, or any highly privileged user. Running it as a standard user in an isolated virtual environment limits the potential blast radius of accidental code execution or malicious behavior hidden within a malformed `.eml` file.

### 🔑 Secret Management
This project utilizes a `.env` file to store sensitive external API keys (**VirusTotal**, **AbuseIPDB**).
**Never commit your `.env` file to version control.**
If an API key is leaked to a public repository, automated scanners (e.g., TruffleHog, GitGuardian) will likely extract and exploit it within minutes. Ensure that your `.gitignore` is properly configured before you push any code.

### 📡 Network Indicators
Threat actors often monitor external scanning services like VirusTotal and AbuseIPDB. While `phish_extractor.py` limits risk by sending **file hashes** rather than raw attachments, submitting an IP, domain, or URL to these platforms inherently alerts the attacker that their infrastructure is being investigated (also known as a "beaconing" effect). For sensitive incidents where operational security (OPSEC) is paramount, **always run the tool with the `--skip-intel` flag.**
