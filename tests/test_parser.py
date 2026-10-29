import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from document_engine.document_engine import parse_document

print("\n" + "="*60)
print("PARSER VALIDATION TEST")
print("="*60 + "\n")

tests = [
    (str(ROOT_DIR / 'document_engine' / 'test_documents' / 'clean' / 'clean_email.eml'), 'email', 'clean'),
    (str(ROOT_DIR / 'document_engine' / 'test_documents' / 'malicious' / 'attack_email.eml'), 'email', 'malicious'),
    (str(ROOT_DIR / 'document_engine' / 'test_documents' / 'clean' / 'clean.html'), 'html', 'clean'),
    (str(ROOT_DIR / 'document_engine' / 'test_documents' / 'malicious' / 'attack.html'), 'html', 'malicious'),
    (str(ROOT_DIR / 'document_engine' / 'test_documents' / 'clean' / 'clean_invoice.pdf'), 'pdf', 'clean'),
]

all_passed = True
for file_path, file_type, category in tests:
    try:
        result = parse_document(file_path, file_type)
        status = "PASS" if not result.get('error') else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"[OK] {category.upper():10} {file_type:6} {status}")
    except Exception as e:
        all_passed = False
        print(f"[ERROR] {category.upper():10} {file_type:6} ERROR: {e}")

print("\n" + "="*60)
print("Tests complete: " + ("ALL PASSED" if all_passed else "SOME FAILED"))
print("="*60 + "\n")
