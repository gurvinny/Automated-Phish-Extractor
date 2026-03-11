# Phish Extractor — Automated IOC Analysis

## Description
A major challenge for Tier 1 SOC analysts is the sheer volume of repetitive tasks, which frequently leads to alert fatigue. **Phish Extractor** is a Python-based automation tool that addresses this by ingesting raw `.eml` phishing reports, extracting critical Indicators of Compromise (IOCs), enriching them with threat intelligence from VirusTotal and AbuseIPDB, and generating human-readable Markdown or JSON reports. By fully automating the manual labor of parsing headers, calculating file hashes, defanging links, and querying APIs, analysts can focus their time on triage, containment, and higher-value incident response tasks.

## Features
- **Header Parsing:** Automatically extracts sender, recipient, subject, dates, and most importantly, SPF, DKIM, and DMARC authentication results.
- **Robust IOC Extraction:** Efficiently pulls URLs, domains, IPv4/IPv6 addresses, and calculates SHA-256 hashes for all file attachments.
- **Defanging:** Defangs URLs, IPs, and domains automatically to ensure indicators can be safely shared across teams and SOAR platforms without accidental execution or triggering enterprise perimeter alerts.
- **Automated Threat Intel Enrichment:** Uses the VirusTotal v3 and AbuseIPDB APIs to check extracted URLs, domains, IPs, and attachment hashes for malicious reputation.
- **Automated Risk Scoring:** Derives an overall risk severity level (LOW, MEDIUM, HIGH, CRITICAL) based on DMARC failures and malicious threat intel hits.

## Prerequisites & Installation
* **Python**: 3.10+
* **OS**: Cross-platform (Windows, macOS, Linux)

For Windows/VS Code users, follow these commands to set up the environment:

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/gurvinny/phish_extractor.git
   cd phish_extractor
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install the dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Configure your API keys:**
   Copy the example environment file and fill in your keys:
   ```powershell
   copy .env.example .env
   ```
   Open `.env` in your editor and add your VirusTotal and AbuseIPDB API keys.

## Usage
Run the tool against any raw `.eml` file to parse and generate a threat report.

### Standard Run
To perform a full analysis with external threat intelligence queries:
```powershell
python phish_extractor.py samples/mock_phish.eml -o report.md
```
*This extracts all IOCs, performs lookups against VirusTotal and AbuseIPDB, and outputs a formatted Markdown report.*

### Offline Mode (--skip-intel)
If you want to extract IOCs and defang them without sending anything to external APIs (useful for highly confidential investigations or OPSEC reasons):
```powershell
python phish_extractor.py samples/mock_phish.eml --skip-intel
```

To see all available CLI options:
```powershell
python phish_extractor.py --help
```

## Detection Engineering
To effectively bridge the gap between reactive analysis and proactive defense, the `detections/` folder is included in this repository. It contains actionable detection rules formulated off of the artifacts parsed by `phish_extractor.py`:
- `yara_rule.yar`: A YARA rule that hunts for the specific SHA256 hash and base64 encoded malicious payload of the fake invoice document attachment in our `mock_phish.eml` sample.
- `sigma_rule.yml`: A Sigma rule designed to detect email gateway logs where DMARC fails and the subject contains the classic phishing lure "URGENT: Your account has been temporarily restricted". This can be integrated into SIEM platforms for real-time alerting.