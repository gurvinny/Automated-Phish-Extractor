# Phishing Email Analysis Report

**Analysis Timestamp:** 2026-09-07T20:32:48.382314+00:00  
**Source File:** `invoice-macro-dropper.eml`  
**Risk Level:** 🟠 **HIGH**

---

## 1 — Email Headers

| Field | Value |
|-------|-------|
| **Subject** | Outstanding invoice INV-40921 - payment overdue |
| **From** | Accounts Payable \<billing@accounts-payable\[.\]example\[.\]org\> |
| **To** | ap@example.com |
| **Date** | Mon, 09 Mar 2026 08:14:22 -0400 |
| **Message-ID** | `\<40921.1741521262@invoice-delivery-secure.example.net\>` |
| **Return-Path** | \<billing@invoice-delivery-secure\[.\]example\[.\]net\> |

### Authentication Results

| Check | Result |
|-------|--------|
| **SPF** | `softfail` |
| **DKIM** | `fail` |
| **DMARC** | `fail` |

### Received Chain (most recent first)

1. `from relay.invoice-delivery-secure.example.net (relay.invoice-delivery-secure.example.net [2001:db8:3c4d:15::1a2b]) by m…`

---

## 2 — Indicators of Compromise (IOCs)

### URLs

- `hxxps://payment-portal-verify[.]example[.]net/account/inv40921`

### Domains

- `accounts-payable[.]example[.]org`
- `invoice-delivery-secure[.]example[.]net`
- `relay[.]invoice-delivery-secure[.]example[.]net`

---

## 3 — Attachments

| Filename | Content-Type | Size (bytes) | SHA-256 |
|----------|-------------|-------------|---------|
| INV-40921.docm | application/vnd.ms-word.document.macroenabled.12 | 56 | `6e7d3c3f385014f139068e49af496c0bdbc01031dac4bb036838e6b35fa5cfb0` |

---

## 4 — Threat Intelligence Enrichment

_No threat intelligence data collected._

---

> **Automated risk assessment: 🟠 HIGH** — Review the IOCs and threat-intel data above before making a final determination.
