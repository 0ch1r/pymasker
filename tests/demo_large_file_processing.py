#!/usr/bin/env python3
"""
Demo script to show the improvements for large file processing.
"""

import os
import tempfile
from string_masker import StringMasker

def create_demo_file(size_mb: int) -> str:
    """Create a demo file of specified size."""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        target_size = size_mb * 1024 * 1024
        current_size = 0
        line_number = 0
        
        patterns = ["SECRET123", "API_KEY_XYZ", "PASSWORD_DEMO"]
        
        while current_size < target_size:
            line_number += 1
            
            # Insert patterns occasionally
            if line_number % 1000 == 0:
                line = f"Line {line_number}: This contains {patterns[line_number % len(patterns)]} for testing.\n"
            else:
                line = f"Line {line_number}: This is just filler text to make the file larger and test memory usage.\n"
            
            f.write(line)
            current_size += len(line.encode('utf-8'))
            
            if current_size >= target_size:
                break
        
        return f.name

def main():
    print("=== Large File Processing Demo ===")
    
    # Create a 100MB test file
    print("Creating a 100MB test file...")
    test_file = create_demo_file(100)
    file_size = os.path.getsize(test_file) / 1024 / 1024
    print(f"Created test file: {file_size:.1f} MB")
    
    # Test patterns
    patterns = ["SECRET123", "API_KEY_XYZ", "PASSWORD_DEMO"]
    
    # Initialize masker with chunked processing
    masker = StringMasker(
        preserve_case=True,
        preserve_length=True,
        seed=42,  # For reproducible results
        chunk_size=1024 * 1024  # 1MB chunks
    )
    
    # Process the large file
    print(f"Processing with patterns: {patterns}")
    print("Using chunked processing for memory efficiency...")
    
    output_file = test_file + ".masked"
    
    try:
        replacement_mapping = masker.mask_file(
            test_file, 
            patterns, 
            output_file, 
            case_sensitive=True, 
            create_backup=False
        )
        
        output_size = os.path.getsize(output_file) / 1024 / 1024
        print(f"✅ Successfully processed {file_size:.1f} MB file!")
        print(f"Output file size: {output_size:.1f} MB")
        print(f"Patterns replaced: {len(replacement_mapping)}")
        
        if replacement_mapping:
            print("\nReplacement mapping:")
            for original, replacement in replacement_mapping.items():
                print(f"  '{original}' -> '{replacement}'")
        
        # Show a sample of the processed content
        print("\nSample of processed content:")
        with open(output_file, 'r') as f:
            lines = f.readlines()[:5]
            for i, line in enumerate(lines, 1):
                print(f"  Line {i}: {line.strip()}")
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
    
    finally:
        # Clean up
        try:
            os.unlink(test_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
        except:
            pass
    
    print("\n=== Key Improvements Made ===")
    print("1. ✅ Increased file size limit from 100MB to 1GB")
    print("2. ✅ Added chunked processing for files > 50MB")
    print("3. ✅ Memory-efficient streaming for large files") 
    print("4. ✅ Configurable chunk size (default: 1MB)")
    print("5. ✅ Automatic selection between in-memory and chunked processing")
    print("6. ⚠️  Pattern spanning chunks needs further refinement")
    
    print("\n=== Usage ===")
    print("For large files, the script now automatically:")
    print("- Uses chunked processing for files > 50MB")
    print("- Processes files up to 1GB in size")
    print("- Maintains low memory usage regardless of file size")
    print("- Provides progress logging for large file operations")

if __name__ == "__main__":
    main()
