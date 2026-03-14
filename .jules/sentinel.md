## 2026-03-14 - Markdown Injection in Report Generator
**Vulnerability:** Found Markdown injection (specifically, table layout breakage) in the report generation phase of `phish_extractor.py`. Attackers can send emails with `|` or newlines in the Subject, From, To, Message-ID or attachment filenames to break the resulting markdown structure.
**Learning:** Any tooling that takes untrusted input and formats it into a structured report (like Markdown) is susceptible to injection/forging.
**Prevention:** Always sanitize user-controlled strings before interpolating them into a structured report (e.g. by escaping `|` to `&#124;` in markdown tables).
