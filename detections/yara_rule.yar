rule Phishing_Invoice_78291 {
    meta:
        author = "gurvinny"
        description = "Detects the specific malicious PDF attachment (Invoice_78291.pdf) or its base64 payload from mock_phish.eml"
        date = "2024-05-29"
        hash1 = "71e4a2e3c287d386ca40134b5bb70c947f4d8bd9cb4265d1bd72bb3d3e8302a5"

    strings:
        // Base64 encoded payload: "This is a fake malicious payload for testing purposes."
        $b64_payload = "VGhpcyBpcyBhIGZha2UgbWFsaWNpb3VzIHBheWxvYWQgZm9yIHRlc3RpbmcgcHVycG9zZXMu" ascii wide
        // Or hunt for the raw string if decoded
        $raw_payload = "This is a fake malicious payload for testing purposes." ascii wide

        $filename = "Invoice_78291.pdf" ascii wide nocase

    condition:
        ($b64_payload or $raw_payload) and $filename
}