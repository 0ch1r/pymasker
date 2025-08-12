# CHANGELOG

## v2.3.0 - Smart IP Address Replacement (2024-08-12)

### 🌟 **Major New Features**

#### Smart IP Address Replacement
- **Revolutionary Change**: IP addresses are now replaced with **valid IP addresses from private subnets** instead of random strings
- **Realistic Anonymization**: Maintains proper network formats for analysis and testing
- **Private Subnets Only**: Uses RFC-compliant private address ranges to avoid conflicts

#### Configurable IP Subnets
- **Default IPv4**: `172.16.0.0/16` - Large private range with 65,534 hosts
- **Default IPv6**: `fd00::/64` - Unique local IPv6 addresses 
- **CLI Configuration**: New `--ipv4-subnet` and `--ipv6-subnet` options
- **Custom Ranges**: Support for any valid subnet specification

### 🔧 **Technical Improvements**

#### Enhanced IP Detection
- **Validation**: Uses Python's `ipaddress` module for strict IP validation
- **Comprehensive Patterns**: Improved regex for IPv4/IPv6 detection
- **Edge Case Handling**: Proper handling of invalid IP formats

#### New API Methods
- `_is_ip_address()` - Validates and identifies IP address types
- `_generate_ipv4_replacement()` - Creates valid IPv4 addresses within subnet
- `_generate_ipv6_replacement()` - Creates valid IPv6 addresses within subnet
- `_get_ip_replacement()` - Handles IP-specific replacement logic

### 📚 **Documentation & Testing**

#### Updated Documentation
- **README.md**: Comprehensive updates with new examples and benefits
- **CLI Help**: Enhanced examples showing IP subnet configuration
- **API Reference**: Updated method signatures and documentation

#### Comprehensive Test Suite
- **test_ip_replacement.txt** - Network infrastructure logs
- **test_network_config.json** - JSON configuration with IP addresses
- **test_apache_logs.txt** - Apache access logs with various IP formats
- **test_ip_masking_demo.py** - Interactive demonstration script
- **test_comprehensive_ip_masking.py** - Full validation test suite
- **IP_REPLACEMENT_README.md** - Detailed feature documentation

### 🎯 **Benefits**

#### For Network Analysis
- **Preserved Format**: IP addresses remain valid for network tools
- **Consistent Mapping**: Same original IP always maps to same replacement
- **Private Ranges**: No risk of generating routable public addresses
- **Topology Preservation**: Maintains logical network relationships

#### For Testing & Development
- **Realistic Data**: Network configurations remain testable
- **Configuration Validation**: Tools can still parse network settings
- **Debugging Support**: Network analysis tools continue to work
- **Compliance**: Meets data anonymization requirements

### 🔄 **Backward Compatibility**

- **Existing Functionality**: All previous features work unchanged
- **Optional Feature**: IP replacement only active with `--filter-ips`
- **Default Behavior**: Safe private subnets used by default
- **Migration**: No changes required for existing usage patterns

### 📊 **Usage Examples**

```bash
# Basic IP filtering (uses 172.16.0.0/16 and fd00::/64)
python3 string_masker.py --file logfile.txt --filter-ips

# Custom IPv4 subnet
python3 string_masker.py --file logs.txt --filter-ips --ipv4-subnet "10.20.0.0/24"

# Custom IPv6 subnet  
python3 string_masker.py --file logs.txt --filter-ips --ipv6-subnet "fc00::/64"

# JSON mode with IP replacement
python3 string_masker.py --json-mode --file config.json --filter-ips

# Combined string and IP filtering
python3 string_masker.py --file data.txt --strings "password" --filter-ips
```

### 🧪 **Test Results**

All comprehensive tests pass:
- ✅ IPv4 replacements within configured subnets
- ✅ IPv6 replacements within configured subnets  
- ✅ Replacement consistency maintained
- ✅ Non-IP strings get random replacements
- ✅ Edge cases handled properly
- ✅ Backward compatibility preserved

---

## v2.2.0 - IP Address Detection (Previous)

### New Features
- Automatic IP address detection with `--filter-ips`
- IPv4 and IPv6 support with comprehensive regex patterns
- IP validation using Python's `ipaddress` module
- Works in both text and JSON modes

### Improvements
- Recursive IP scanning in JSON structures
- Enhanced examples and documentation
- Combined filtering with existing string masking

---

## v2.1.0 - JSON Processing Mode

### New Features
- JSON processing mode with key-based masking
- Nested object and array support
- JSON structure preservation and formatting control
- File-based JSON key input

---

## v2.0.0 - Chunked Processing

### New Features
- Chunked processing for large files (up to 1GB)
- Memory-efficient streaming architecture
- Configurable chunk sizes
- Automatic processing method selection

---

## v1.0.0 - Initial Release

### Core Features
- Security-focused design
- Format preservation
- Command-line interface
- Programmatic API
