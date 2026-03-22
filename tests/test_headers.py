import pytest
from phish_extractor import _extract_auth_result

def test_extract_auth_result():
    auth_header = "spf=pass (sender IP is 1.2.3.4); dkim=fail (bad signature); dmarc=softfail action=none;"
    
    assert _extract_auth_result(auth_header, "spf") == "pass"
    assert _extract_auth_result(auth_header, "dkim") == "fail"
    assert _extract_auth_result(auth_header, "dmarc") == "softfail"
    
def test_extract_auth_result_not_found():
    auth_header = "spf=pass (sender IP is 1.2.3.4);"
    
    assert _extract_auth_result(auth_header, "dkim") == "not found"
