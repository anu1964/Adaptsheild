"""
Validate detection accuracy on test files
Run: python validate_detection.py
"""

import json
import os
import sys

def validate_detection():
    """Validate detection accuracy against requirements"""
    results_file = 'document_engine/results/parsing_results.json'
    
    if not os.path.exists(results_file):
        print("\n✗ parsing_results.json not found.")
        print("  Run: python save_parser_results.py first\n")
        return False
    
    with open(results_file, 'r', encoding='utf-8') as f:
        results = json.load(f)
    
    print("\n" + "="*70)
    print("DETECTION ACCURACY VALIDATION")
    print("="*70 + "\n")
    
    malicious_docs = [r for r in results if r.get('file_category') == 'malicious']
    benign_docs = [r for r in results if r.get('file_category') == 'clean']
    
    print(f"Total documents: {len(results)}")
    print(f"Malicious documents: {len(malicious_docs)}")
    print(f"Benign documents: {len(benign_docs)}\n")
    
    # ===== REQUIREMENT 1: Malicious Detection Rate =====
    print("-" * 70)
    print("REQUIREMENT 1: Malicious Document Detection")
    print("-" * 70)
    
    malicious_detected = sum(1 for r in malicious_docs if r.get('hidden_flags') and len(r.get('hidden_flags', [])) > 0)
    malicious_accuracy = (malicious_detected / len(malicious_docs) * 100) if malicious_docs else 0
    
    print(f"Detection Rate: {malicious_accuracy:.1f}% ({malicious_detected}/{len(malicious_docs)})")
    print(f"Requirement: ≥80%")
    malicious_pass = malicious_accuracy >= 80
    print(f"Status: {'✓ PASS' if malicious_pass else '✗ FAIL'}\n")
    
    # Show which malicious docs were detected
    print("Malicious documents analysis:")
    for doc in malicious_docs:
        flags = doc.get('hidden_flags', [])
        status = "✓ DETECTED" if flags else "✗ MISSED"
        print(f"  {status:15} {doc.get('source_file', 'unknown'):40} flags: {flags}")
    print()
    
    # ===== REQUIREMENT 2: False Positive Rate =====
    print("-" * 70)
    print("REQUIREMENT 2: False Positive Rate (Benign Documents)")
    print("-" * 70)
    
    false_positives = sum(1 for r in benign_docs if r.get('hidden_flags') and len(r.get('hidden_flags', [])) > 0)
    fp_rate = (false_positives / len(benign_docs) * 100) if benign_docs else 0
    
    print(f"False Positive Rate: {fp_rate:.1f}% ({false_positives}/{len(benign_docs)})")
    print(f"Requirement: <20%")
    fp_pass = fp_rate < 20
    print(f"Status: {'✓ PASS' if fp_pass else '✗ FAIL'}\n")
    
    # Show which benign docs had false positives
    print("Benign documents analysis:")
    for doc in benign_docs:
        flags = doc.get('hidden_flags', [])
        status = "✗ FALSE POSITIVE" if flags else "✓ CORRECT"
        print(f"  {status:20} {doc.get('source_file', 'unknown'):40} flags: {flags}")
    print()
    
    # ===== REQUIREMENT 3: Performance =====
    print("-" * 70)
    print("REQUIREMENT 3: Performance (<3 seconds per file)")
    print("-" * 70)
    
    processing_times = [r.get('processing_time_seconds', 0) for r in results if r.get('processing_time_seconds')]
    if processing_times:
        max_time = max(processing_times)
        avg_time = sum(processing_times) / len(processing_times)
        
        print(f"Average: {avg_time:.3f}s")
        print(f"Maximum: {max_time:.3f}s")
        print(f"Requirement: <3s")
        perf_pass = max_time < 3
        print(f"Status: {'✓ PASS' if perf_pass else '✗ FAIL'}\n")
    else:
        print("✗ No timing data\n")
        perf_pass = False
    
    # ===== REQUIREMENT 4: File Count =====
    print("-" * 70)
    print("REQUIREMENT 4: Minimum Test Files")
    print("-" * 70)
    
    file_count_pass = len(results) >= 10
    print(f"Test files: {len(results)}")
    print(f"Requirement: ≥10")
    print(f"Status: {'✓ PASS' if file_count_pass else '✗ FAIL'}\n")
    
    # ===== SUMMARY =====
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    
    all_pass = malicious_pass and fp_pass and perf_pass and file_count_pass
    
    print(f"✓ Malicious Detection (≥80%): {'PASS' if malicious_pass else 'FAIL'}")
    print(f"✓ False Positive Rate (<20%): {'PASS' if fp_pass else 'FAIL'}")
    print(f"✓ Performance (<3s): {'PASS' if perf_pass else 'FAIL'}")
    print(f"✓ File Count (≥10): {'PASS' if file_count_pass else 'FAIL'}")
    print()
    
    if all_pass:
        print("🎉 ALL REQUIREMENTS MET - READY FOR GIT PUSH")
    else:
        print("⚠ SOME REQUIREMENTS NOT MET - NEEDS WORK")
    
    print("=" * 70 + "\n")
    
    return all_pass

if __name__ == '__main__':
    success = validate_detection()
    sys.exit(0 if success else 1)