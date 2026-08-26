# Sample Corpus

Eight synthetic messages used by the test suite and for demonstrating the tool.
Every address, domain and IP is drawn from the ranges reserved for documentation
(RFC 2606 `example.com` / `.org` / `.net`, RFC 5737 and RFC 3849 address blocks),
so nothing here points at real infrastructure.

## `malicious/`

| Sample | What it exercises | Expected risk |
|---|---|---|
| `credential-phish.eml` | Classic credential harvest: SPF/DKIM/DMARC all fail, lookalike sender domain, URL in both the plain and HTML parts, PDF attachment | HIGH |
| `invoice-macro-dropper.eml` | Macro-enabled attachment, quoted-printable body, SPF softfail, and a **compressed IPv6 address** in the Received chain | CRITICAL |
| `bec-wire-transfer.eml` | Business email compromise: **no URL, no attachment, and SPF/DKIM both pass.** Carries only a display-name spoof and a Reply-To pointing off-domain | HIGH |

The BEC sample is the important one. It is invisible to reputation feeds and
attachment sandboxing — there is nothing to look up. It is caught by comparing
the claimed sender identity against the address that would actually receive a
reply.

## `clean/`

| Sample | What it exercises |
|---|---|
| `newsletter-legitimate.eml` | Marketing mail that passes all authentication, with a bounce **subdomain** in the envelope sender — the pattern a naive identity check would false-positive on |
| `internal-notice.eml` | Plain-text internal mail with no indicators at all |
| `receipt-with-attachment.eml` | Legitimate transactional mail carrying a PDF, so attachments alone do not imply risk |

All three must score `LOW` with zero identity mismatches, and the test suite
asserts exactly that. They exist to catch false positives, which are the failure
mode that actually erodes trust in a triage tool.

## `edge/`

| Sample | What it exercises |
|---|---|
| `malformed-and-traversal.eml` | A bare `From: broken@`, a part declaring `charset="definitely-not-a-charset"`, nested multipart, and an attachment named `../../etc/passwd` |
| `markdown-injection.eml` | A subject full of markdown control characters, to confirm report generation escapes attacker-controlled text |

The first of these found two genuine crashes when it was written: the malformed
`From` raises `IndexError` inside Python's own header parser, and the bogus
charset raises `LookupError` from the codec lookup. Both would have ended the
run. Since every input to this tool is attacker-controlled by definition, that
class of bug is treated as a defect, not as bad input.

## A note on IP indicators

Documentation IP ranges are **not globally routable**, and the tool deliberately
filters non-routable addresses so private and reserved hops are never sent to
reputation APIs. A consequence is that these samples produce no IP indicators
even where an address appears in the headers — that is the filter working, not a
parsing failure. Real captures will surface IP IOCs normally.
