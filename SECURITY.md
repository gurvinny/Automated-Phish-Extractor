# Security Policy

## Supported Versions

The following versions of the Phish Extractor tool are currently supported with security updates. We rely on the core language features introduced in Python 3.10+, and no earlier versions are supported.

| Version | Supported          | Python Version Required |
| ------- | ------------------ | ----------------------- |
| 1.0.x   | :white_check_mark: | 3.10+                   |
| < 1.0   | :x:                | N/A                     |

## Reporting a Vulnerability

Please do not open a public issue for security vulnerabilities. Instead, contact me directly via email at:
[Insert Your Email Here]

Or, you can reach out via my GitHub profile:
https://github.com/gurvinny

I will do my best to acknowledge the vulnerability and respond as soon as possible.

## Threat Model

### Execution Context
This script interacts directly with external files (`.eml`, `.msg`, etc.) and performs network operations. Under no circumstances should this tool be run as an Administrator, Root, or any highly privileged user. Running it as a standard user in an isolated virtual environment limits the potential blast radius of accidental code execution or malicious behavior hidden within an `.eml` file.

### Secret Management
This project utilizes a `.env` file to store sensitive external API keys (VirusTotal, AbuseIPDB). **Never commit your `.env` file to version control.** If an API key is leaked to a public repository, automated scanners will likely extract and exploit it within minutes. Ensure that your `.gitignore` is properly configured before you push any code.

### Network Indicators
Threat actors often monitor external scanning services like VirusTotal and AbuseIPDB. While `phish_extractor.py` limits risk by sending file hashes rather than raw attachments, submitting an IP, domain, or URL to these platforms alerts the attacker that their infrastructure is being investigated. For sensitive incidents where operational security (OPSEC) is paramount, always run the tool with the `--skip-intel` flag.