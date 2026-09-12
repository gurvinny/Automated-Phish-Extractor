# Sample Corpus

Eight synthetic messages used by the test suite and for demonstrating the tool.
Recipients, internal hosts and every IP address are drawn from the ranges reserved
for documentation (RFC 2606 `example.com` / `.org` / `.net`, RFC 5737 and RFC 3849),
so nothing here resolves to real infrastructure.

The one exception is deliberate: `credential-phish.eml` needs a *lookalike* sender
domain for the scenario to make sense, and a reserved domain cannot look like a
brand. It uses invented strings such as `paypal-support-update.com`. These are
registrable names rather than reserved ones — they are not owned by this project
and are not resolved, contacted or submitted to any API by the test suite, which
runs fully offline.

## `malicious/`

Verdicts below are what an **offline** run produces (`--skip-intel`), which is how
the test suite scores them. A live run can score higher if VirusTotal or AbuseIPDB
returns a confirmed-malicious hit, but never lower.

| Sample | What it exercises | Offline risk |
|---|---|---|
| `credential-phish.eml` | Classic credential harvest: SPF/DKIM/DMARC all fail, lookalike sender domain, URL in both the plain and HTML parts, PDF attachment | `HIGH` |
| `invoice-macro-dropper.eml` | Macro-enabled attachment, quoted-printable body, SPF softfail, and a **compressed IPv6 address** in the Received chain | `HIGH` |
| `bec-wire-transfer.eml` | Business email compromise: **no URL, no attachment, and SPF/DKIM both pass.** Carries only a display-name spoof and a Reply-To pointing off-domain | `MEDIUM` |

The BEC sample is the important one. It is invisible to reputation feeds and
attachment sandboxing — there is nothing to look up. It is caught by comparing
the claimed sender identity against the address that would actually receive a
reply.

It scores `MEDIUM` rather than `HIGH`, and that is the honest result: with no URL,
no attachment and passing authentication, the identity mismatch is the *only*
signal available. Raising it further would mean inflating a single indicator into
a verdict the evidence does not support.

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

## `test_report.md`

A committed example of the Markdown output, regenerated from a real run:

```bash
python3 phish_extractor.py samples/malicious/invoice-macro-dropper.eml --skip-intel \
  -f markdown -o samples/test_report.md
```

It is generated with `--skip-intel` on purpose. An offline run is deterministic
and reproducible by anyone who clones the repo, whereas a live run would bake in
VirusTotal and AbuseIPDB responses that change over time and would go stale the
same way the previous version of this file did. Its **Threat Intelligence**
section is therefore empty — that is the flag working, not a missing feature.
