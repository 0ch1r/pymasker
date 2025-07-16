#!/usr/bin/env python3
"""
Test script for chunked processing functionality.
Creates a large test file and verifies that chunked processing works correctly.
"""

import os
import tempfile
import string
import random
from pathlib import Path
from string_masker import StringMasker

def create_large_test_file(file_path: str, size_mb: int) -> str:
    """Create a large test file with known patterns."""
    
    # Patterns to embed in the file
    patterns = [
        "SECRET_PASSWORD_123",
        "API_KEY_xyz789",
        "CONFIDENTIAL_DATA",
        "token_abc_def_456",
        "super_secret_value"
    ]
    
    # Create content
    content_lines = []
    target_size = size_mb * 1024 * 1024
    current_size = 0
    line_number = 0
    
    while current_size < target_size:
        line_number += 1
        
        # Every 100 lines, insert one of our patterns
        if line_number % 100 == 0:
            pattern = random.choice(patterns)
            line = f"Line {line_number}: This line contains {pattern} which should be masked.\n"
        else:
            # Generate random content
            random_text = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=80))
            line = f"Line {line_number}: {random_text}\n"
        
        content_lines.append(line)
        current_size += len(line.encode('utf-8'))
        
        # Stop if we've reached the target size
        if current_size >= target_size:
            break
    
    # Write to file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(content_lines)
    
    return patterns

def test_chunked_vs_memory_processing():
    """Test that chunked processing produces the same results as in-memory processing."""
    
    print("=== Testing Chunked vs In-Memory Processing ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a moderately sized test file (5MB)
        test_file = os.path.join(temp_dir, "test_input.txt")
        patterns = create_large_test_file(test_file, 5)
        
        print(f"Created test file: {test_file}")
        print(f"File size: {os.path.getsize(test_file) / 1024 / 1024:.2f} MB")
        print(f"Test patterns: {patterns}")
        
        # Test in-memory processing (small chunk size to force chunked processing)
        masker_chunked = StringMasker(
            preserve_case=True,
            preserve_length=True,
            seed=42,  # Use seed for reproducible results
            chunk_size=64 * 1024  # 64KB chunks
        )
        
        # Force chunked processing by using the chunked method directly
        output_chunked = os.path.join(temp_dir, "output_chunked.txt")
        mapping_chunked = masker_chunked.mask_file_chunked(
            test_file, patterns, output_chunked, case_sensitive=True, create_backup=False
        )
        
        # Test in-memory processing
        masker_memory = StringMasker(
            preserve_case=True,
            preserve_length=True,
            seed=42,  # Same seed for same results
            chunk_size=64 * 1024
        )
        
        output_memory = os.path.join(temp_dir, "output_memory.txt")
        mapping_memory = masker_memory._mask_file_in_memory(
            Path(test_file), patterns, output_memory, case_sensitive=True, create_backup=False
        )
        
        # Compare results
        with open(output_chunked, 'r') as f1, open(output_memory, 'r') as f2:
            content_chunked = f1.read()
            content_memory = f2.read()
        
        print(f"\nResults:")
        print(f"Chunked output size: {len(content_chunked)} characters")
        print(f"Memory output size: {len(content_memory)} characters")
        print(f"Contents match: {content_chunked == content_memory}")
        print(f"Chunked replacements: {len(mapping_chunked)}")
        print(f"Memory replacements: {len(mapping_memory)}")
        
        if content_chunked == content_memory:
            print("✅ Chunked processing produces identical results to in-memory processing!")
        else:
            print("❌ Chunked processing produces different results!")
            # Show first difference
            for i, (c1, c2) in enumerate(zip(content_chunked, content_memory)):
                if c1 != c2:
                    print(f"First difference at position {i}: '{c1}' vs '{c2}'")
                    print(f"Context: ...{content_chunked[max(0, i-20):i+20]}...")
                    break

def test_large_file_processing():
    """Test processing of a large file that would use chunked processing."""
    
    print("\n=== Testing Large File Processing ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a large test file (60MB to trigger chunked processing)
        test_file = os.path.join(temp_dir, "large_test_input.txt")
        patterns = create_large_test_file(test_file, 60)
        
        file_size_mb = os.path.getsize(test_file) / 1024 / 1024
        print(f"Created large test file: {test_file}")
        print(f"File size: {file_size_mb:.2f} MB")
        
        # This should automatically use chunked processing
        masker = StringMasker(
            preserve_case=True,
            preserve_length=True,
            seed=42,
            chunk_size=1024 * 1024  # 1MB chunks
        )
        
        output_file = os.path.join(temp_dir, "large_output.txt")
        
        print("Processing large file...")
        mapping = masker.mask_file(
            test_file, patterns, output_file, case_sensitive=True, create_backup=False
        )
        
        output_size_mb = os.path.getsize(output_file) / 1024 / 1024
        print(f"Output file size: {output_size_mb:.2f} MB")
        print(f"Replacements made: {len(mapping)}")
        
        # Verify some patterns were found and replaced
        if len(mapping) > 0:
            print("✅ Large file processing completed successfully!")
            print("Sample replacements:")
            for i, (original, replacement) in enumerate(list(mapping.items())[:3]):
                print(f"  '{original}' -> '{replacement}'")
        else:
            print("❌ No patterns were found in the large file!")

def test_pattern_spanning_chunks():
    """Test that patterns spanning chunk boundaries are handled correctly."""
    
    print("\n=== Testing Pattern Spanning Chunks ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a test file where a pattern spans chunk boundaries
        test_file = os.path.join(temp_dir, "span_test.txt")
        
        chunk_size = 100  # Very small chunk size
        pattern = "SPANNING_PATTERN_TEST"
        
        # Create content where the pattern spans the chunk boundary
        content_part1 = "A" * (chunk_size - 10)  # First part
        content_part2 = pattern  # Pattern that will span boundary
        content_part3 = "B" * 50  # Final part
        
        content = content_part1 + content_part2 + content_part3
        
        with open(test_file, 'w') as f:
            f.write(content)
        
        print(f"Created span test file with pattern at position {len(content_part1)}")
        print(f"Chunk size: {chunk_size}, Pattern: '{pattern}'")
        print(f"Pattern should span from chunk 1 to chunk 2")
        
        # Process with small chunks
        masker = StringMasker(
            preserve_case=True,
            preserve_length=True,
            seed=42,
            chunk_size=chunk_size
        )
        
        output_file = os.path.join(temp_dir, "span_output.txt")
        mapping = masker.mask_file_chunked(
            test_file, [pattern], output_file, case_sensitive=True, create_backup=False
        )
        
        # Check if pattern was found and replaced
        with open(output_file, 'r') as f:
            result_content = f.read()
        
        print(f"Pattern found and replaced: {pattern in mapping}")
        if pattern in mapping:
            print(f"✅ Pattern spanning chunks was handled correctly!")
            print(f"'{pattern}' -> '{mapping[pattern]}'")
        else:
            print(f"❌ Pattern spanning chunks was not detected!")
            print(f"Original pattern '{pattern}' still in output: {pattern in result_content}")

if __name__ == "__main__":
    try:
        test_chunked_vs_memory_processing()
        test_large_file_processing()
        test_pattern_spanning_chunks()
        print("\n🎉 All tests completed!")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
