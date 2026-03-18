<div align="center">

# Contributing to Phish Extractor 🎣

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/gurvinny/phish_extractor/graphs/commit-activity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  Help us build a faster, more secure way for SOC analysts to fight phishing.
</p>

---

</div>

First off, thank you for considering contributing to Phish Extractor! It’s people like you who make this a better tool for the SOC community.

As a project intended for a professional cybersecurity portfolio, we maintain high standards for code quality, security, and documentation.

---

## 🛠️ How Can I Contribute?

### Reporting Bugs
- Check the [Issues Tab](https://github.com/gurvinny/Automated-Phish-Extractor/issues) to see if the bug has already been reported.
- If not, open a new issue. Use the appropriate **severity** and **type** labels (e.g., `type: bug`).
- Include your OS, Python version, and a small snippet of the error log.

### Suggesting Enhancements
- Open an issue with the tag `type: enhancement`.
- Describe the specific SOC use-case the feature would solve (e.g., "Adding an O365 API integration to pull emails directly").

### Pull Requests (PRs)
1. **Fork the repo** and create your branch from `main`.
2. **Install dev dependencies** and ensure you are using a virtual environment.
3. **Keep it focused:** A PR should ideally solve one issue or add one feature.
4. **Follow the style:** We use [Black](https://github.com/psf/black) for Python formatting.
5. **Security First:** - Never commit your `.env` file or actual API keys.
    - Ensure all extracted indicators are defanged before being printed to the console/reports.
    - If modifying API logic, ensure rate limits (like VirusTotal's 4/min) are respected.

---

## 🚦 Pull Request Process

1. **Self-Review:** Does the code work? Does it handle API rate limits?
2. **Update Docs:** If you added a new CLI flag (like `--workers`), update the `README.md`.
3. **Open the PR:** Provide a clear description of what you changed.
4. **Review:** I (@gurvinny) will review your code. I might ask for small changes to keep the project consistent with its goal of being a SOC portfolio piece.
5. **Merge:** Once approved, your code will be merged into `main` and you'll be added to the contributors list!

---

## ⚖️ License
By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

## 💬 Communication
If you have questions, feel free to comment on the specific issue you are working on. I try to respond to all contributors within 24–48 hours.
