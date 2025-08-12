#!/bin/bash

# Test script for CLI-based IP masking functionality

echo "=== CLI IP Masking Tests ==="
echo

cd /mnt/mac/Users/jerichorivera/Workspace/github/pymasker

# Test 1: Basic IP filtering with default subnets
echo "Test 1: Basic IP filtering (default subnets: 172.16.0.0/16, fd00::/64)"
python3 string_masker.py --file tests/test_ip_replacement.txt --filter-ips --output /tmp/test1_output.txt --show-mapping --verbose
echo "Output saved to /tmp/test1_output.txt"
echo

# Test 2: Custom IPv4 subnet
echo "Test 2: Custom IPv4 subnet (10.10.0.0/24)"
python3 string_masker.py --file tests/test_apache_logs.txt --filter-ips --ipv4-subnet "10.10.0.0/24" --output /tmp/test2_output.txt --show-mapping --verbose
echo "Output saved to /tmp/test2_output.txt"
echo

# Test 3: JSON mode with IP filtering
echo "Test 3: JSON mode with IP filtering"
python3 string_masker.py --json-mode --file tests/test_network_config.json --filter-ips --output /tmp/test3_output.json --show-mapping --verbose
echo "Output saved to /tmp/test3_output.json"
echo

# Test 4: Combined string and IP filtering
echo "Test 4: Combined string and IP filtering"
python3 string_masker.py --file tests/test_ip_replacement.txt --strings "password" "secret" "token" --filter-ips --output /tmp/test4_output.txt --show-mapping --verbose
echo "Output saved to /tmp/test4_output.txt"
echo

# Test 5: Custom IPv6 subnet
echo "Test 5: Custom IPv6 subnet (fc00::/64)"
python3 string_masker.py --file tests/test_ip_replacement.txt --filter-ips --ipv6-subnet "fc00::/64" --output /tmp/test5_output.txt --show-mapping --verbose
echo "Output saved to /tmp/test5_output.txt"
echo

# Test 6: Help message to show new options
echo "Test 6: Help message showing new IP subnet options"
python3 string_masker.py --help | grep -A5 -B5 "subnet\|filter-ips"
echo

echo "=== All CLI tests completed ==="
echo "Check the output files in /tmp/ to see the results"
