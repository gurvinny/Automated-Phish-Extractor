# Phishing Email Analysis Report

**Analysis Timestamp:** 2026-03-11T21:20:16.426599+00:00  
**Source File:** `mock_phish.eml`  
**Risk Level:** 🟡 **MEDIUM**

---

## 1 — Email Headers

| Field | Value |
|-------|-------|
| **Subject** | URGENT: Your account has been temporarily restricted |
| **From** | PayPal Security <alerts@paypal-support-update[.]com> |
| **To** | victim@yourcompany.com |
| **Date** | Wed, 11 Mar 2026 10:00:00 -0400 |
| **Message-ID** | `<9876543210@evil-phishing-domain.net>` |
| **Return-Path** | <bounces@evil-phishing-domain[.]net> |

### Authentication Results

| Check | Result |
|-------|--------|
| **SPF** | `fail` |
| **DKIM** | `none` |
| **DMARC** | `fail` |

### Received Chain (most recent first)

1. `from mail.evil-phishing-domain.net (mail.evil-phishing-domain.net [198.51.100.42]) by mx.yourcompany.com with ESMTP id 1…`

---

## 2 — Indicators of Compromise (IOCs)

### URLs

- `hxxp://secure-update-billing-verification[.]com/login.php?session=8932`

### Domains

- `login[.]php`

---

## 3 — Attachments

| Filename | Content-Type | Size (bytes) | SHA-256 |
|----------|-------------|-------------|---------|
| Invoice_78291.pdf | application/pdf | 54 | `71e4a2e3c287d386ca40134b5bb70c947f4d8bd9cb4265d1bd72bb3d3e8302a5` |

---

## 4 — Threat Intelligence Enrichment

_No threat intelligence data collected._

---

> **Automated risk assessment: 🟡 MEDIUM** — Review the IOCs and threat-intel data above before making a final determination.
