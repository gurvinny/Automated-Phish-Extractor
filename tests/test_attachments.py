import hashlib
from email.message import EmailMessage
from phish_extractor import extract_attachments

def test_extract_attachments():
    msg = EmailMessage()
    msg['Subject'] = 'Test with attachment'
    
    # Add a text part
    msg.set_content('Please see the attached file')
    
    # Add an attachment
    payload_bytes = b'malicious payload here'
    msg.add_attachment(payload_bytes, maintype='application', subtype='octet-stream', filename='evil.exe')
    
    attachments = extract_attachments(msg)
    
    assert len(attachments) == 1
    assert attachments[0].filename == 'evil.exe'
    assert attachments[0].content_type == 'application/octet-stream'
    assert attachments[0].size_bytes == len(payload_bytes)
    assert attachments[0].sha256 == hashlib.sha256(payload_bytes).hexdigest()

def test_extract_attachments_no_filename():
    msg = EmailMessage()
    msg['Subject'] = 'Test with nameless attachment'
    
    msg.set_content('Please see the attached file')
    payload_bytes = b'test'
    msg.add_attachment(payload_bytes, maintype='application', subtype='octet-stream')
    
    attachments = extract_attachments(msg)
    
    assert len(attachments) == 1
    assert attachments[0].filename == 'unnamed_attachment'
