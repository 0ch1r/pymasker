# IP Address Replacement Functionality

## Overview

The PyMasker tool has been enhanced to replace IP addresses with **valid IP addresses from private subnets** instead of random strings. This provides more realistic anonymization while maintaining network-valid formats.

## Key Features

### 🌐 **Smart IP Detection and Replacement**
- **IPv4 Support**: Detects and validates IPv4 addresses (0-255 per octet)
- **IPv6 Support**: Comprehensive IPv6 detection including compressed notation
- **Validation**: Uses Python's `ipaddress` module for validation
- **Private Subnets**: Replaces with addresses from configurable private ranges

### 🔧 **Configurable Subnets**
- **Default IPv4**: `172.16.0.0/16` (RFC 1918 private range)
- **Default IPv6**: `fd00::/64` (RFC 4193 unique local addresses)
- **Customizable**: Use `--ipv4-subnet` and `--ipv6-subnet` CLI options

### ✅ **Consistent Replacements**
- Same IP address always gets the same replacement
- Cached mappings ensure consistency across large files
- Deterministic with seed for reproducible results

## Usage Examples

### Basic IP Filtering
```bash
# Use default subnets (172.16.0.0/16, fd00::/64)
python3 string_masker.py --file logfile.txt --filter-ips
```

### Custom Subnets
```bash
# Custom IPv4 subnet  
python3 string_masker.py --file logs.txt --filter-ips --ipv4-subnet "10.10.0.0/24"

# Custom IPv6 subnet
python3 string_masker.py --file logs.txt --filter-ips --ipv6-subnet "fc00::/64"

# Both custom subnets
python3 string_masker.py --file logs.txt --filter-ips \
    --ipv4-subnet "192.168.100.0/24" \
    --ipv6-subnet "fd12:3456::/64"
```

### Combined Filtering
```bash
# IP addresses AND specific strings
python3 string_masker.py --file data.txt --strings "password" "token" --filter-ips

# JSON mode with IP filtering
python3 string_masker.py --json-mode --file config.json --json-keys "password" --filter-ips
```

## Before vs After Examples

### IPv4 Replacement
```
Original:  192.168.1.100
Masked:    172.16.176.255  (from 172.16.0.0/16)

Original:  203.0.113.50  
Masked:    172.16.233.178  (from 172.16.0.0/16)
```

### IPv6 Replacement  
```
Original:  2001:db8::1
Masked:    fd00::42a4:2807:3fc1:635a  (from fd00::/64)

Original:  fe80::1
Masked:    fd00::ea5:add6:f9ee:3fb6   (from fd00::/64)
```

### Apache Log Example
**Before:**
```
192.168.1.50 - - [12/Aug/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 2326
203.0.113.25 - - [12/Aug/2024:10:00:02 +0000] "POST /api/login HTTP/1.1" 200 1234  
```

**After (with --ipv4-subnet "10.20.0.0/24"):**
```
10.20.0.137 - - [12/Aug/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 2326
10.20.0.27 - - [12/Aug/2024:10:00:02 +0000] "POST /api/login HTTP/1.1" 200 1234
```

## Test Files

The `tests/` directory contains comprehensive test files:

- **`test_ip_replacement.txt`**: Mixed IPv4/IPv6 addresses with various formats
- **`test_network_config.json`**: JSON configuration with network settings
- **`test_apache_logs.txt`**: Apache access log format with IP addresses
- **`test_ip_masking_demo.py`**: Interactive demonstration script  
- **`test_comprehensive_ip_masking.py`**: Full test suite validating all functionality
- **`test_cli_ip_masking.sh`**: CLI testing script with various subnet configurations

## Benefits

### 🎯 **Realistic Anonymization**
- Maintains valid IP format for downstream processing
- Uses private/non-routable address ranges
- Preserves network analysis capabilities

### 🔒 **Security Focused**  
- No risk of generating public IP addresses
- Uses RFC-compliant private ranges
- Cryptographically secure random generation (by default)

### ⚡ **Performance**
- Efficient IP detection with regex + validation
- Cached replacements for consistency
- Works with existing chunked processing for large files

### 🛠 **Flexibility**
- Configurable subnet ranges
- Works in both text and JSON modes
- Combines with existing string filtering
- Supports custom random seeds for testing

## Technical Implementation

### IP Detection
- Uses comprehensive regex patterns for IPv4/IPv6 detection
- Validates matches with `ipaddress.IPv4Address()` and `ipaddress.IPv6Address()`
- Handles compressed IPv6 notation, embedded IPv4, etc.

### Replacement Generation
- IPv4: Random selection from configured subnet's host range
- IPv6: Random host identifier within configured network prefix  
- Fallback to original random string behavior for non-IP strings

### Subnet Configuration
- Default subnets chosen for maximum compatibility
- `172.16.0.0/16`: Large private range (RFC 1918)
- `fd00::/64`: Unique local IPv6 range (RFC 4193)
- Supports any valid subnet specification

## Running Tests

```bash
# Interactive demo
python3 tests/test_ip_masking_demo.py

# Comprehensive validation
python3 tests/test_comprehensive_ip_masking.py

# CLI testing
bash tests/test_cli_ip_masking.sh
```

## Migration Notes

- **Backward Compatible**: Existing functionality unchanged
- **Optional Feature**: IP replacement only active with `--filter-ips`
- **Default Behavior**: Uses safe private subnets by default
- **Configuration**: Subnet ranges configurable via CLI arguments
