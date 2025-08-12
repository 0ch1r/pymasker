#!/usr/bin/env python3
"""
Demonstration script for IP address masking functionality.
Tests the new IP-specific replacement features.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from string_masker import StringMasker
import json

def test_ipv4_replacement():
    """Test IPv4 address replacement with private subnets."""
    print("=== Testing IPv4 Address Replacement ===")
    
    # Test with default 172.16.0.0/16 subnet
    masker = StringMasker()
    
    test_ips = [
        "192.168.1.100",
        "10.0.0.25", 
        "203.0.113.50",
        "8.8.8.8"
    ]
    
    print("Original IPs -> Masked IPs (172.16.0.0/16 subnet):")
    for ip in test_ips:
        masked = masker._get_replacement(ip)
        print(f"  {ip} -> {masked}")
    
    # Test consistency - same IP should get same replacement
    print(f"\nConsistency test:")
    print(f"  192.168.1.100 -> {masker._get_replacement('192.168.1.100')}")
    print(f"  192.168.1.100 -> {masker._get_replacement('192.168.1.100')} (should be same)")
    
    # Test with custom subnet
    print(f"\nTesting with custom IPv4 subnet (10.10.0.0/24):")
    masker_custom = StringMasker(ipv4_subnet="10.10.0.0/24")
    for ip in test_ips[:2]:
        masked = masker_custom._get_replacement(ip)
        print(f"  {ip} -> {masked}")

def test_ipv6_replacement():
    """Test IPv6 address replacement."""
    print("\n=== Testing IPv6 Address Replacement ===")
    
    masker = StringMasker()
    
    test_ipv6s = [
        "2001:db8::1",
        "2001:0db8:85a3::8a2e:0370:7334", 
        "::1",
        "fe80::1"
    ]
    
    print("Original IPv6s -> Masked IPv6s (fd00::/64 subnet):")
    for ip in test_ipv6s:
        masked = masker._get_replacement(ip)
        print(f"  {ip} -> {masked}")

def test_mixed_content():
    """Test masking of mixed content (IPs + regular strings)."""
    print("\n=== Testing Mixed Content Masking ===")
    
    masker = StringMasker()
    
    test_strings = [
        "192.168.1.100",    # IPv4
        "password123",       # Regular string 
        "2001:db8::1",      # IPv6
        "api_key_xyz",      # Regular string
        "10.0.0.50"         # IPv4
    ]
    
    print("Mixed content masking:")
    for s in test_strings:
        masked = masker._get_replacement(s)
        print(f"  '{s}' -> '{masked}'")

def test_text_file_masking():
    """Test full file masking with IP addresses."""
    print("\n=== Testing File-Based IP Masking ===")
    
    masker = StringMasker(ipv4_subnet="172.20.0.0/16")
    
    # Create sample text content
    sample_text = """
Server log entries:
2024-08-12 - Client from 192.168.1.50 accessed /login
2024-08-12 - Database at 10.0.0.100 responding
2024-08-12 - IPv6 client 2001:db8::dead:beef connected
2024-08-12 - Load balancer 203.0.113.10 active
"""
    
    # Find IPs
    detected_ips = masker.find_ip_addresses(sample_text)
    print(f"Detected IP addresses: {sorted(detected_ips)}")
    
    # Mask the text
    masked_text, mapping = masker.mask_strings_in_text(sample_text, list(detected_ips))
    
    print(f"\nOriginal text:")
    print(sample_text)
    print(f"Masked text:")
    print(masked_text)
    
    print(f"\nIP Replacement Mapping:")
    for original, replacement in mapping.items():
        print(f"  {original} -> {replacement}")

def test_json_ip_masking():
    """Test JSON-based IP masking."""
    print("\n=== Testing JSON IP Masking ===")
    
    masker = StringMasker()
    
    sample_json = {
        "servers": {
            "web": "192.168.1.10",
            "db": "10.0.0.50", 
            "api_key": "secret123"
        },
        "ipv6_endpoints": [
            "2001:db8::1",
            "fe80::1"
        ]
    }
    
    # Find IPs in JSON
    detected_ips = masker.find_ip_addresses_in_json(sample_json)
    print(f"IPs found in JSON: {sorted(detected_ips)}")
    
    # Convert to string for masking
    json_str = json.dumps(sample_json, indent=2)
    masked_json_str, mapping = masker.mask_strings_in_text(json_str, list(detected_ips))
    
    print(f"\nOriginal JSON:")
    print(json_str)
    print(f"Masked JSON:")
    print(masked_json_str)

def test_ip_validation():
    """Test that only valid IPs are detected and replaced."""
    print("\n=== Testing IP Validation ===")
    
    masker = StringMasker()
    
    test_strings = [
        "192.168.1.1",     # Valid IPv4 - should be replaced
        "999.999.999.999", # Invalid IPv4 - should NOT be replaced
        "300.1.1.1",       # Invalid IPv4 - should NOT be replaced  
        "2001:db8::1",     # Valid IPv6 - should be replaced
        "hello.world.com", # Not an IP - should NOT be replaced
        "password123",     # Regular string - should be replaced with random
        "127.0.0.1"        # Valid IPv4 - should be replaced
    ]
    
    print("Testing IP validation and replacement:")
    for s in test_strings:
        ip_type = masker._is_ip_address(s)
        replacement = masker._get_replacement(s)
        print(f"  '{s}' -> IP type: {ip_type}, Replacement: '{replacement}'")

if __name__ == "__main__":
    print("IP Address Masking Functionality Demo")
    print("=" * 50)
    
    test_ipv4_replacement()
    test_ipv6_replacement()
    test_mixed_content()
    test_text_file_masking()
    test_json_ip_masking()
    test_ip_validation()
    
    print("\n" + "=" * 50)
    print("Demo completed! All IP addresses are now replaced with valid")
    print("private network addresses instead of random strings.")
