#!/usr/bin/env python3
"""
Demo script showcasing JSON masking CLI functionality.
"""

import os
import json
import subprocess
import tempfile

def run_command(cmd):
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def main():
    print("=== JSON Masking CLI Demo ===\n")
    
    # Create a complex test JSON file
    complex_data = {
        "app_config": {
            "name": "MyApp",
            "version": "1.0.0",
            "database": {
                "host": "db.example.com",
                "port": 5432,
                "credentials": {
                    "username": "app_user",
                    "password": "ultra_secret_db_password_123",
                    "admin_password": "super_admin_secret_456"
                }
            },
            "external_apis": [
                {
                    "service": "payment_gateway",
                    "endpoint": "https://api.payments.com",
                    "api_key": "pk_live_payment_key_abc123",
                    "webhook_secret": "whsec_payment_webhook_789"
                },
                {
                    "service": "email_service", 
                    "endpoint": "https://api.email.com",
                    "api_key": "sg_live_email_key_def456",
                    "webhook_secret": "whsec_email_webhook_012"
                }
            ],
            "security": {
                "jwt_secret": "jwt_signing_secret_xyz789",
                "encryption_key": "aes_encryption_key_123abc",
                "session_secret": "session_secret_456def"
            },
            "features": {
                "debug_mode": False,
                "rate_limiting": True,
                "max_requests_per_minute": 1000
            }
        }
    }
    
    # Write test file
    test_file = "demo_config.json"
    with open(test_file, 'w') as f:
        json.dump(complex_data, f, indent=2)
    
    print(f"Created test file: {test_file}")
    print("Original configuration (first 15 lines):")
    with open(test_file, 'r') as f:
        lines = f.readlines()
        for i, line in enumerate(lines[:15]):
            print(f"{i+1:2d}: {line.rstrip()}")
    print("    ... (truncated)")
    
    print("\n" + "="*60)
    print("Demo 1: Basic JSON key masking")
    print("="*60)
    
    cmd1 = f'python3 string_masker.py --json-mode --file {test_file} --json-keys "password" "api_key" "secret" --output demo1_output.json --no-backup'
    print(f"Command: {cmd1}")
    
    returncode, stdout, stderr = run_command(cmd1)
    print(f"Exit code: {returncode}")
    print(f"Output: {stdout.strip()}")
    
    if returncode == 0:
        print("\nMasked output (first 15 lines):")
        with open("demo1_output.json", 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines[:15]):
                print(f"{i+1:2d}: {line.rstrip()}")
        print("    ... (truncated)")
    
    print("\n" + "="*60)
    print("Demo 2: Case-insensitive matching with custom keys")
    print("="*60)
    
    # Create keys file
    keys_file = "sensitive_keys.txt"
    with open(keys_file, 'w') as f:
        f.write("PASSWORD\nAPI_KEY\nSECRET\nwebhook_secret\njwt_secret\n")
    
    cmd2 = f'python3 string_masker.py --json-mode --file {test_file} --json-keys-file {keys_file} --ignore-case --output demo2_output.json --json-indent 0 --no-backup'
    print(f"Command: {cmd2}")
    
    returncode, stdout, stderr = run_command(cmd2)
    print(f"Exit code: {returncode}")
    print(f"Output: {stdout.strip()}")
    
    if returncode == 0:
        print("\nCompact masked output (first 200 chars):")
        with open("demo2_output.json", 'r') as f:
            content = f.read()
            print(content[:200] + "...")
    
    print("\n" + "="*60)
    print("Demo 3: Verbose output with mapping display")
    print("="*60)
    
    cmd3 = f'python3 string_masker.py --json-mode --file {test_file} --json-keys "secret" "password" --output demo3_output.json --verbose --show-mapping --no-backup'
    print(f"Command: {cmd3}")
    
    returncode, stdout, stderr = run_command(cmd3)
    print(f"Exit code: {returncode}")
    if stderr:
        print("Stderr:")
        print(stderr.strip())
    print("Stdout:")
    print(stdout.strip())
    
    print("\n" + "="*60)
    print("Demo 4: Error handling - Invalid JSON mode usage")
    print("="*60)
    
    cmd4 = f'python3 string_masker.py --json-mode --file {test_file}'
    print(f"Command: {cmd4}")
    
    returncode, stdout, stderr = run_command(cmd4)
    print(f"Exit code: {returncode}")
    print(f"Error message: {stdout.strip()}")
    
    print("\n" + "="*60)
    print("Demo 5: Mixed usage - Text mode for comparison")
    print("="*60)
    
    cmd5 = f'python3 string_masker.py --file {test_file} --strings "ultra_secret_db_password_123" "pk_live_payment_key_abc123" --output demo5_output.json --no-backup'
    print(f"Command: {cmd5}")
    
    returncode, stdout, stderr = run_command(cmd5)
    print(f"Exit code: {returncode}")
    print(f"Output: {stdout.strip()}")
    
    if returncode == 0:
        print("\nText mode result (searches for literal strings):")
        with open("demo5_output.json", 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines[:10]):
                print(f"{i+1:2d}: {line.rstrip()}")
    
    # Cleanup
    cleanup_files = [
        test_file, keys_file, "demo1_output.json", "demo2_output.json", 
        "demo3_output.json", "demo5_output.json"
    ]
    
    for file in cleanup_files:
        try:
            os.unlink(file)
        except:
            pass
    
    print("\n" + "="*60)
    print("🎉 JSON CLI Demo Completed!")
    print("="*60)
    print("\nKey Features Demonstrated:")
    print("✅ JSON mode with --json-mode flag")
    print("✅ Key-based masking with --json-keys")
    print("✅ File-based key input with --json-keys-file")
    print("✅ Case-insensitive key matching with --ignore-case")
    print("✅ Compact/indented output with --json-indent")
    print("✅ Verbose logging and mapping display")
    print("✅ Error handling for invalid usage")
    print("✅ Comparison with traditional text mode")
    
    print("\nJSON Mode vs Text Mode:")
    print("📝 Text Mode: Searches for literal string values anywhere in the file")
    print("🔑 JSON Mode: Masks values specifically associated with JSON keys")
    print("🎯 JSON Mode: Preserves JSON structure and handles nested objects/arrays")

if __name__ == "__main__":
    main()
