from document_engine import parse_document

print("\n" + "="*60)
print("PARSER VALIDATION TEST")
print("="*60 + "\n")

tests = [
    ('document_engine\\test_documents\\clean\\clean_email.eml', 'email', 'clean'),
    ('document_engine\\test_documents\\malicious\\attack_email.eml', 'email', 'malicious'),
    ('document_engine\\test_documents\\clean\\clean.html', 'html', 'clean'),
    ('document_engine\\test_documents\\malicious\\attack.html', 'html', 'malicious'),
    ('document_engine\\test_documents\\clean\\clean_invoice.pdf', 'pdf', 'clean'),
]

for file_path, file_type, category in tests:
    try:
        result = parse_document(file_path, file_type)
        status = "PASS" if not result.get('error') else "FAIL"
        print(f"✓ {category.upper():10} {file_type:6} {status}")
    except Exception as e:
        print(f"✗ {category.upper():10} {file_type:6} ERROR: {e}")

print("\n" + "="*60)
print("✓ Tests complete")
print("="*60 + "\n")