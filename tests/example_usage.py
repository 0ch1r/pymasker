#!/usr/bin/env python3
"""
Example usage of the StringMasker class for programmatic use.
"""

from string_masker import StringMasker

def main():
    print("=== StringMasker Programmatic Usage Examples ===\n")
    
    # Example 1: Basic text masking
    print("1. Basic Text Masking:")
    masker = StringMasker()
    
    text = "The password is secret123 and the API key is abc-def-789"
    target_strings = ["secret123", "abc-def-789"]
    
    masked_text, mapping = masker.mask_strings_in_text(text, target_strings)
    
    print(f"Original: {text}")
    print(f"Masked:   {masked_text}")
    print(f"Mapping:  [REDACTED - {len(mapping)} replacements]\n")
    
    # Example 2: Case-insensitive masking
    print("2. Case-insensitive Masking:")
    text = "Username: ADMIN, password: Secret123, API_KEY: xyz789"
    target_strings = ["admin", "secret123", "api_key"]
    
    masked_text, mapping = masker.mask_strings_in_text(text, target_strings, case_sensitive=False)
    
    print(f"Original: {text}")
    print(f"Masked:   {masked_text}")
    print(f"Mapping:  [REDACTED - {len(mapping)} replacements]\n")
    
    # Example 3: Custom configuration
    print("3. Custom Configuration (no case preservation, custom chars):")
    custom_masker = StringMasker(
        preserve_case=False,
        preserve_length=True,
        random_chars="XYZABC123",
        seed=999
    )
    
    text = "Token: MySecretToken123"
    target_strings = ["MySecretToken123"]
    
    masked_text, mapping = custom_masker.mask_strings_in_text(text, target_strings)
    
    print(f"Original: {text}")
    print(f"Masked:   {masked_text}")
    print(f"Mapping:  [REDACTED - {len(mapping)} replacements]\n")
    
    # Example 4: Processing multiple texts with consistent replacements
    print("4. Consistent Replacements Across Multiple Texts:")
    consistent_masker = StringMasker(seed=42)
    
    texts = [
        "Database: server=localhost;password=secret123",
        "Config: password=secret123;timeout=30",
        "Log: Failed login with password=secret123"
    ]
    
    target_strings = ["secret123", "localhost"]
    
    print("Processing multiple texts:")
    for i, text in enumerate(texts, 1):
        masked_text, mapping = consistent_masker.mask_strings_in_text(text, target_strings)
        print(f"  Text {i}: {text}")
        print(f"  Masked: {masked_text}")
    
    print(f"\nFinal replacement cache: [REDACTED - {len(consistent_masker.replacement_cache)} cached replacements]")

if __name__ == '__main__':
    main()
