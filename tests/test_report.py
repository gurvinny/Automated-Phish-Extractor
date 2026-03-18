import pytest
from phish_extractor import safe_md

def test_safe_md():
    assert safe_md("Hello|World") == "Hello&#124;World"
    assert safe_md("Hello\nWorld") == "Hello World"
    assert safe_md("Hello\rWorld") == "HelloWorld"
    assert safe_md(None) == "None"
    assert safe_md("Normal string") == "Normal string"
