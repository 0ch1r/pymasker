#!/usr/bin/env python3
"""
Comprehensive test suite for IP address masking functionality.
Validates that IP addresses are replaced with valid IPs from specified subnets.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from string_masker import StringMasker
import ipaddress
import tempfile
import json

def test_ipv4_subnet_validation():
    """Test that IPv4 replacements are within the specified subnet."""
    print("=== Testing IPv4 Subnet Validation ===")
    
    test_subnet = "10.100.0.0/24"
    masker = StringMasker(ipv4_subnet=test_subnet)
    network = ipaddress.IPv4Network(test_subnet)
    
    test_ips = ["192.168.1.100", "203.0.113.50", "8.8.8.8"]
    
    print(f"Testing replacements are within {test_subnet}:")
    all_valid = True
    
    for original_ip in test_ips:
        replacement = masker._get_replacement(original_ip)
        try:
            replacement_ip = ipaddress.IPv4Address(replacement)
            is_in_subnet = replacement_ip in network
            print(f"  {original_ip} -> {replacement} (in subnet: {is_in_subnet})")
            if not is_in_subnet:
                all_valid = False
        except ipaddress.AddressValueError:
            print(f"  {original_ip} -> {replacement} (INVALID IP FORMAT!)")
            all_valid = False
    
    print(f"All IPv4 replacements valid: {all_valid}")
    return all_valid

def test_ipv6_subnet_validation():
    """Test that IPv6 replacements are within the specified subnet."""
    print("\n=== Testing IPv6 Subnet Validation ===")
    
    test_subnet = "fc00:1234::/64"
    masker = StringMasker(ipv6_subnet=test_subnet)
    network = ipaddress.IPv6Network(test_subnet)
    
    test_ips = ["2001:db8::1", "fe80::1", "::1"]
    
    print(f"Testing replacements are within {test_subnet}:")
    all_valid = True
    
    for original_ip in test_ips:
        replacement = masker._get_replacement(original_ip)
        try:
            replacement_ip = ipaddress.IPv6Address(replacement)
            is_in_subnet = replacement_ip in network
            print(f"  {original_ip} -> {replacement} (in subnet: {is_in_subnet})")
            if not is_in_subnet:
                all_valid = False
        except ipaddress.AddressValueError:
            print(f"  {original_ip} -> {replacement} (INVALID IP FORMAT!)")
            all_valid = False
    
    print(f"All IPv6 replacements valid: {all_valid}")
    return all_valid

def test_consistency():
    """Test that same IP always gets same replacement."""
    print("\n=== Testing Replacement Consistency ===")
    
    masker = StringMasker()
    test_ip = "192.168.1.100"
    
    replacements = [masker._get_replacement(test_ip) for _ in range(5)]
    all_same = all(r == replacements[0] for r in replacements)
    
    print(f"Testing consistency for {test_ip}:")
    print(f"  Replacements: {set(replacements)}")
    print(f"  All same: {all_same}")
    
    return all_same

def test_non_ip_strings():
    """Test that non-IP strings still get random replacements."""
    print("\n=== Testing Non-IP String Handling ===")
    
    masker = StringMasker()
    test_strings = ["password123", "api_key_xyz", "hello.world.com", "not_an_ip"]
    
    print("Testing non-IP strings get random replacements:")
    all_non_ip = True
    
    for s in test_strings:
        replacement = masker._get_replacement(s)
        is_ipv4 = masker._is_ip_address(replacement) == 'ipv4'
        is_ipv6 = masker._is_ip_address(replacement) == 'ipv6'
        print(f"  '{s}' -> '{replacement}' (is IP: {is_ipv4 or is_ipv6})")
        
        if is_ipv4 or is_ipv6:
            all_non_ip = False
    
    print(f"All non-IP strings got non-IP replacements: {all_non_ip}")
    return all_non_ip

def test_file_processing():
    """Test complete file processing with IP replacement."""
    print("\n=== Testing File Processing ===")
    
    # Create test content
    test_content = """
Log file with various IP addresses:
192.168.1.100 - Client connected
10.0.0.50 - Database responding  
2001:db8::1 - IPv6 client active
password123 - This should get random replacement
203.0.113.25 - External client
"""
    
    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        masker = StringMasker(ipv4_subnet="10.200.0.0/24")
        
        # Detect IPs
        ips = masker.find_ip_addresses(test_content)
        print(f"Detected IPs: {sorted(ips)}")
        
        # Mask content
        masked_content, mapping = masker.mask_strings_in_text(test_content, list(ips))
        
        print("Original content:")
        print(test_content)
        print("Masked content:")
        print(masked_content)
        
        # Validate replacements
        valid_replacements = True
        ipv4_network = ipaddress.IPv4Network("10.200.0.0/24")
        
        for original, replacement in mapping.items():
            ip_type = masker._is_ip_address(original)
            if ip_type == 'ipv4':
                try:
                    repl_ip = ipaddress.IPv4Address(replacement)
                    if repl_ip not in ipv4_network:
                        valid_replacements = False
                        print(f"ERROR: {replacement} not in subnet!")
                except:
                    valid_replacements = False
                    print(f"ERROR: {replacement} is not a valid IPv4!")
        
        print(f"All IP replacements in correct subnet: {valid_replacements}")
        return valid_replacements
        
    finally:
        os.unlink(temp_file)

def test_edge_cases():
    """Test edge cases and error conditions."""
    print("\n=== Testing Edge Cases ===")
    
    # Test with very small subnet
    try:
        masker = StringMasker(ipv4_subnet="192.168.1.1/32")  # Single host
        replacement = masker._get_replacement("10.0.0.1")
        print(f"Single host subnet replacement: {replacement}")
    except Exception as e:
        print(f"Single host subnet error: {e}")
    
    # Test invalid IPs are not replaced as IPs
    masker = StringMasker()
    invalid_ips = ["999.999.999.999", "300.1.1.1", "256.256.256.256"]
    
    print("Testing invalid IPs are not treated as IPs:")
    for invalid in invalid_ips:
        ip_type = masker._is_ip_address(invalid)
        replacement = masker._get_replacement(invalid)
        is_replacement_ip = masker._is_ip_address(replacement) is not None
        print(f"  {invalid} -> IP type: {ip_type}, replacement is IP: {is_replacement_ip}")
    
    return True

def run_all_tests():
    """Run all tests and return overall success."""
    print("IP Address Masking Comprehensive Test Suite")
    print("=" * 60)
    
    tests = [
        test_ipv4_subnet_validation,
        test_ipv6_subnet_validation, 
        test_consistency,
        test_non_ip_strings,
        test_file_processing,
        test_edge_cases
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"Test {test.__name__} failed with error: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("Test Results:")
    for i, (test, result) in enumerate(zip(tests, results)):
        status = "PASS" if result else "FAIL"
        print(f"  {test.__name__}: {status}")
    
    all_passed = all(results)
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    return all_passed

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
