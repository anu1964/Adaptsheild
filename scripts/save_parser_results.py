"""
Run parser on all test files and save results to parsing_results.json
Run: python save_parser_results.py
"""

import os
import json
import time
from pathlib import Path
from document_engine import parse_document

def save_parser_results():
    """Parse all test documents and save results"""
    results = []
    test_dirs = [
        'document_engine/test_documents/clean',
        'document_engine/test_documents/malicious'
    ]
    
    os.makedirs('document_engine/results', exist_ok=True)
    
    print("\n" + "="*70)
    print("PARSING ALL TEST DOCUMENTS")
    print("="*70 + "\n")
    
    file_count = 0
    
    for test_dir in test_dirs:
        if not os.path.exists(test_dir):
            print(f"⚠ Directory not found: {test_dir}")
            continue
        
        for file_name in sorted(os.listdir(test_dir)):
            file_path = os.path.join(test_dir, file_name)
            
            if not os.path.isfile(file_path):
                continue
            
            # Determine file type from extension
            ext = Path(file_name).suffix.lower()
            if ext == '.pdf':
                file_type = 'pdf'
            elif ext in ['.eml', '.msg']:
                file_type = 'email'
            elif ext in ['.html', '.htm']:
                file_type = 'html'
            elif ext in ['.docx', '.doc']:
                file_type = 'docx'
            else:
                continue
            
            # Parse and time it
            start = time.time()
            try:
                result = parse_document(file_path, file_type)
                elapsed = time.time() - start
                
                result['processing_time_seconds'] = round(elapsed, 3)
                result['file_category'] = 'clean' if 'clean' in test_dir else 'malicious'
                result['file_path'] = file_path
                results.append(result)
                
                status = "✓" if not result.get('error') else "✗"
                print(f"{status} {file_name:40} {elapsed:.3f}s  {file_type}")
                file_count += 1
            except Exception as e:
                print(f"✗ {file_name:40} ERROR: {str(e)[:50]}")
    
    # Save to JSON
    output_path = 'document_engine/results/parsing_results.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "="*70)
    print(f"✓ Results saved to {output_path}")
    print(f"✓ Total files processed: {file_count}")
    print("="*70 + "\n")

if __name__ == '__main__':
    save_parser_results()