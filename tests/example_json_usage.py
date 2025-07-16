#!/usr/bin/env python3
"""
Example usage of JSON masking functionality in StringMasker.
"""

import json
from string_masker import StringMasker

def main():
    print("=== JSON Masking Examples ===\n")
    
    # Example 1: Basic JSON masking
    print("1. Basic JSON Key Masking:")
    
    sample_data = {
        "user": {
            "username": "john_doe",
            "password": "secret123",
            "email": "john@example.com"
        },
        "api": {
            "api_key": "sk_live_abc123xyz",
            "secret": "webhook_secret_456"
        },
        "config": {
            "debug": True,
            "timeout": 30
        }
    }
    
    masker = StringMasker(seed=42)  # For reproducible output
    target_keys = ["password", "api_key", "secret"]
    
    masked_data, mapping = masker.mask_json_by_keys(sample_data, target_keys)
    
    print("Original JSON:")
    print(json.dumps(sample_data, indent=2))
    print("\nMasked JSON:")
    print(json.dumps(masked_data, indent=2))
    print(f"\nMasked {len(mapping)} fields")
    
    # Example 2: Case-insensitive key matching
    print("\n" + "="*50)
    print("2. Case-Insensitive Key Matching:")
    
    mixed_case_data = {
        "Database": {
            "PASSWORD": "admin123",
            "Api_Key": "key_mixed_case",
            "normal_field": "not_masked"
        }
    }
    
    # Using case-insensitive matching
    masked_mixed, mapping_mixed = masker.mask_json_by_keys(
        mixed_case_data, 
        ["password", "api_key"],  # lowercase keys
        case_sensitive=False
    )
    
    print("Original (mixed case):")
    print(json.dumps(mixed_case_data, indent=2))
    print("\nMasked (case-insensitive):")
    print(json.dumps(masked_mixed, indent=2))
    
    # Example 3: Nested arrays and objects
    print("\n" + "="*50)
    print("3. Nested Structures:")
    
    nested_data = {
        "services": [
            {
                "name": "service1",
                "password": "service1_pass",
                "api_key": "key1_abc"
            },
            {
                "name": "service2", 
                "password": "service2_pass",
                "api_key": "key2_def"
            }
        ],
        "global": {
            "admin": {
                "password": "admin_global_pass"
            }
        }
    }
    
    masked_nested, mapping_nested = masker.mask_json_by_keys(
        nested_data,
        ["password", "api_key"]
    )
    
    print("Original nested:")
    print(json.dumps(nested_data, indent=2))
    print("\nMasked nested:")
    print(json.dumps(masked_nested, indent=2))
    
    # Example 4: Numeric values
    print("\n" + "="*50)
    print("4. Numeric Value Masking:")
    
    numeric_data = {
        "user_id": 12345,
        "balance": 999.99,
        "pin": 1234,
        "name": "John Doe"
    }
    
    masked_numeric, mapping_numeric = masker.mask_json_by_keys(
        numeric_data,
        ["user_id", "balance", "pin"]
    )
    
    print("Original with numbers:")
    print(json.dumps(numeric_data, indent=2))
    print("\nMasked with numbers:")
    print(json.dumps(masked_numeric, indent=2))
    
    print("\n" + "="*50)
    print("🎉 JSON masking examples completed!")
    print("\nKey Benefits:")
    print("✅ Preserves JSON structure and formatting")
    print("✅ Handles nested objects and arrays")
    print("✅ Supports case-sensitive/insensitive key matching")
    print("✅ Masks string and numeric values")
    print("✅ Maintains consistent replacements")

if __name__ == "__main__":
    main()
