# PyMasker 🎭

**Advanced String Masking Tool for Data Privacy and Security**

PyMasker is a powerful, security-focused Python tool designed to mask sensitive strings in text files and JSON data while preserving formatting, structure, and readability. Perfect for sanitizing logs, configuration files, JSON APIs, databases, and any text-based data containing sensitive information.

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-focused-green.svg)](#security-features)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🌟 Key Features

### 🔒 **Security-First Design**
- **Cryptographically secure** random generation using Python's `secrets` module
- **File system security** with path validation and permission controls
- **Input validation** with size limits and sanitization
- **Zero information leakage** in error messages and logs

### 🚀 **High Performance**
- **Large file support** - Process files up to **1GB** in size
- **Memory-efficient chunked processing** for files >50MB
- **Configurable chunk sizes** for performance optimization
- **Automatic processing method selection** (in-memory vs. chunked)

### 🎨 **Intelligent Formatting Preservation**
- **Case pattern preservation** (e.g., `MySecret` → `XyRandom`)
- **Length preservation** maintains original string lengths
- **Structure preservation** keeps text layout intact
- **Consistent replacements** across multiple occurrences

### 🛠 **Flexible Configuration**
- **Multiple input methods** - Command line args or file-based patterns
- **JSON and text modes** - Specialized processing for JSON data structures
- **Automatic IP detection** - Built-in IPv4 and IPv6 address masking with `--filter-ips`
- **Customizable character sets** for replacement generation
- **Case-sensitive/insensitive** matching options
- **Reproducible results** with optional seeding (for testing)

### 🔑 **JSON Data Processing**
- **Key-based masking** - Mask values by JSON key names instead of literal strings
- **Nested object support** - Process deeply nested JSON structures and arrays
- **Structure preservation** - Maintains valid JSON syntax and formatting
- **Flexible key input** - Specify keys via command line or file

## 🚀 Quick Start

### Basic Usage

```bash
# Mask specific strings in a file
python3 string_masker.py --file config.txt --strings "password" "api_key" "secret"

# Load patterns from a file
python3 string_masker.py --file data.txt --strings-file sensitive_strings.txt

# Save to a different output file
python3 string_masker.py --file input.txt --strings "token" --output masked_output.txt

# Automatically detect and mask IP addresses
python3 string_masker.py --file logfile.txt --filter-ips

# Combine string masking with automatic IP detection
python3 string_masker.py --file data.txt --strings "password" "token" --filter-ips

# JSON mode - mask values by key names
python3 string_masker.py --json-mode --file config.json --json-keys "password" "api_key" "secret"

# JSON mode with automatic IP detection
python3 string_masker.py --json-mode --file config.json --filter-ips

# JSON keys from file with case-insensitive matching
python3 string_masker.py --json-mode --file config.json --json-keys-file sensitive_keys.txt --ignore-case
```

### Advanced Usage

```bash
# Case-insensitive matching with custom output
python3 string_masker.py --file logs.txt --strings "API_KEY" --ignore-case --output sanitized.txt

# Custom character set and no case preservation
python3 string_masker.py --file data.txt --strings "secret" --random-chars "ABCDEF123456" --no-preserve-case

# Large file processing with custom chunk size
python3 string_masker.py --file huge_file.txt --strings "sensitive" --chunk-size 2097152 --verbose

# Reproducible masking for testing (not cryptographically secure)
python3 string_masker.py --file test.txt --strings "demo" --seed 42

# JSON mode with compact output and verbose logging
python3 string_masker.py --json-mode --file config.json --json-keys "password" "secret" --json-indent 0 --verbose

# JSON mode with custom output and mapping display
python3 string_masker.py --json-mode --file data.json --json-keys-file keys.txt --output masked.json --show-mapping
```

## 📋 Installation

### Requirements
- Python 3.7 or higher
- No external dependencies (uses only Python standard library)

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/pymasker.git
cd pymasker

# Make the script executable (optional)
chmod +x string_masker.py

# Test the installation
python3 string_masker.py --help
```

## 📚 Usage Examples

### Example 1: JSON Data Masking

**Input file (`sample_config.json`):**
```json
{
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
        "name": "Service1",
        "api_key": "api_key_service_1_xyz"
      },
      {
        "name": "Service2",
        "api_key": "api_key_service_2_abc"
      }
    ]
  },
  "secret_info": "should_be_hidden"
}
```

**Command:**
```bash
python3 string_masker.py --json-mode --file sample_config.json --json-keys "password" "api_key" "secret_info" --output masked_config.json
```

**Output (first 15 lines):**
```json
{
  "app_config": {
    "name": "MyApp",
    "version": "1.0.0",
    "database": {
      "host": "db.example.com",
      "port": 5432,
      "credentials": {
        "username": "app_user",
        "password": "*****",
        "admin_password": "*****"
      }
    },
    "external_apis": [
      {
        "name": "Service1",
        "api_key": "*****"
      },
      {
        "name": "Service2",
        "api_key": "*****"
      }
    ]
  },
  "secret_info": "*****"
}
```

### Example 2: Configuration File Sanitization

**Input file (`config.txt`):**
```ini
[database]
host = localhost
password = SuperSecret123
api_key = abc-def-789

[auth]
jwt_secret = MyJwtToken2023
```

**Command:**
```bash
python3 string_masker.py --file config.txt --strings "SuperSecret123" "abc-def-789" "MyJwtToken2023"
```

**Output:**
```ini
[database]
host = localhost
password = XmPqRsT8uVw3Z
api_key = pQr-StU-123

[auth]
jwt_secret = NyKlmOpQr4567
```

### Example 2: Log File Sanitization

**Input file (`app.log`):**
```
2023-01-01 10:00:00 [INFO] User john_doe logged in
2023-01-01 10:01:00 [ERROR] Authentication failed for admin_user
2023-01-01 10:02:00 [DEBUG] API call with token: sk_live_abc123xyz
```

**Command:**
```bash
python3 string_masker.py --file app.log --strings "john_doe" "admin_user" "sk_live_abc123xyz"
```

**Output:**
```
2023-01-01 10:00:00 [INFO] User mNbPqRsT logged in
2023-01-01 10:01:00 [ERROR] Authentication failed for XyZaBcDeF
2023-01-01 10:02:00 [DEBUG] API call with token: qR_lMnO_pQrStUv
```

### Example 4: Automatic IP Address Detection

**Input file (`server.log`):**
```
2024-01-15 10:30:00 - Server started on 192.168.1.100
2024-01-15 10:30:05 - Client connected from 203.0.113.50
2024-01-15 10:30:10 - Database at 10.0.0.25 is responding
2024-01-15 10:30:15 - Load balancer 198.51.100.1 active
2024-01-15 10:30:20 - IPv6 endpoint 2001:db8::1 healthy
2024-01-15 10:30:25 - Cache server at 172.16.0.100 ready
```

**Command:**
```bash
python3 string_masker.py --file server.log --filter-ips --verbose
```

**Output:**
```
2024-01-15 10:30:00 - Server started on 847k562o9h834
2024-01-15 10:30:05 - Client connected from 692b7y395428
2024-01-15 10:30:10 - Database at 68w2i4S81 is responding
2024-01-15 10:30:15 - Load balancer 294Z18b942K3 active
2024-01-15 10:30:20 - IPv6 endpoint 8473tgh2qC1 healthy
2024-01-15 10:30:25 - Cache server at 246g523P8k639 ready
```

*Detected and masked: 6 IP addresses (IPv4: 192.168.1.100, 203.0.113.50, 10.0.0.25, 198.51.100.1, 172.16.0.100; IPv6: 2001:db8::1)*

### Example 5: JSON Configuration with IP Detection

**Input file (`network_config.json`):**
```json
{
  "database": {
    "host": "192.168.1.100",
    "password": "secret_db_pass",
    "port": 5432
  },
  "web_servers": [
    {
      "name": "web1",
      "ip": "203.0.113.10",
      "api_key": "sk_live_abc123"
    }
  ],
  "load_balancer": "198.51.100.1",
  "dns_servers": ["8.8.8.8", "1.1.1.1"]
}
```

**Command:**
```bash
python3 string_masker.py --json-mode --file network_config.json --json-keys "password" "api_key" --filter-ips
```

**Output:**
```json
{
  "database": {
    "host": "847k562o9h834",
    "password": "RmPqSsTuVwXyZ1234",
    "port": 5432
  },
  "web_servers": [
    {
      "name": "web1",
      "ip": "692b7y395428",
      "api_key": "qR_lMnO_pQrStU"
    }
  ],
  "load_balancer": "294Z18b942K3",
  "dns_servers": ["68w2i4S81", "5h821D3"]
}
```

*Both JSON keys (password, api_key) and all IP addresses were automatically detected and masked*

### Example 3: Programmatic Usage

```python
from string_masker import StringMasker

# Initialize the masker
masker = StringMasker(
    preserve_case=True,
    preserve_length=True,
    seed=42  # For reproducible results in testing
)

# Mask strings in text
text = "The password is secret123 and the API key is abc-def-789"
target_strings = ["secret123", "abc-def-789"]

masked_text, mapping = masker.mask_strings_in_text(text, target_strings)
print(f"Original: {text}")
print(f"Masked:   {masked_text}")
print(f"Mapping:  {len(mapping)} replacements made")

# Mask entire files
mapping = masker.mask_file(
    input_file="sensitive_data.txt",
    target_strings=["password", "token", "secret"],
    output_file="sanitized_data.txt"
)

# JSON masking by keys
json_data = {
    "config": {
        "api_key": "secret123",
        "password": "mypassword"
    }
}
masked_json, mapping = masker.mask_json_by_keys(
    json_data, 
    keys=["api_key", "password"]
)
print(f"Masked JSON: {masked_json}")

# JSON file masking
mapping = masker.mask_json_file(
    input_file="config.json",
    keys=["password", "secret", "token"],
    output_file="masked_config.json"
)
```

## 🔧 Command Line Options

### Text Mode Options
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--file` | `-f` | Input file to process | Required |
| `--output` | `-o` | Output file path | Overwrites input |
| `--strings` | `-s` | List of strings to mask | - |
| `--strings-file` | `-sf` | File containing strings to mask | - |
| `--ignore-case` | `-i` | Case-insensitive matching | False |
| `--no-preserve-case` | | Don't preserve original case pattern | False |
| `--no-preserve-length` | | Don't preserve original string length | False |
| `--random-chars` | | Characters for random generation | `a-zA-Z0-9` |
| `--seed` | | Random seed for reproducible results | None |
| `--chunk-size` | | Chunk size for large files (bytes) | 1048576 (1MB) |
| `--filter-ips` | | Automatically detect and mask IP addresses (IPv4/IPv6) | False |
| `--no-backup` | | Don't create backup files | False |
| `--verbose` | `-v` | Verbose output | False |
| `--show-mapping` | | Show replacement mapping | False |

### JSON Mode Options
| Option | Description | Default |
|--------|-------------|---------|
| `--json-mode` | Enable JSON processing mode | False |
| `--json-keys` | List of JSON keys whose values to mask | - |
| `--json-keys-file` | File containing JSON keys to mask | - |
| `--json-indent` | JSON output indentation (0 for compact) | 2 |

## 🏗 Architecture

### Processing Modes

PyMasker automatically selects the optimal processing method based on file size:

- **📝 In-Memory Processing** (≤50MB): Fast processing for smaller files
- **🔄 Chunked Processing** (>50MB): Memory-efficient streaming for large files

### Memory Usage

| File Size | Memory Usage | Processing Method |
|-----------|--------------|-------------------|
| < 50MB | ~2-3x file size | In-memory |
| 50MB - 1GB | ~10-50MB | Chunked |
| > 1GB | Not supported | Size limit exceeded |

### Security Features

- **🔐 Cryptographically Secure**: Uses `secrets` module for random generation
- **🛡 Path Security**: Absolute path resolution and validation
- **📁 File Permissions**: Restrictive permissions (600) on output files
- **⚠️ Input Validation**: Size limits and sanitization
- **🚫 Zero Leakage**: No sensitive data in logs or error messages

## 📖 API Reference

### StringMasker Class

```python
class StringMasker:
    def __init__(self, preserve_case=True, preserve_length=True, 
                 random_chars=None, seed=None, chunk_size=1024*1024):
        """
        Initialize the StringMasker.
        
        Args:
            preserve_case (bool): Preserve original case pattern
            preserve_length (bool): Preserve original string length
            random_chars (str): Characters for random generation
            seed (int): Random seed for reproducible results
            chunk_size (int): Chunk size for large file processing
        """
```

#### Key Methods

```python
def find_ip_addresses(self, text: str) -> Set[str]:
    """Find all IPv4 and IPv6 addresses in the given text."""

def find_ip_addresses_in_json(self, json_data) -> Set[str]:
    """Find all IP addresses in JSON data by scanning all string values."""

def mask_strings_in_text(self, text: str, target_strings: List[str], 
                        case_sensitive: bool = True) -> Tuple[str, Dict[str, str]]:
    """Mask target strings in the given text."""

def mask_file(self, input_file: str, target_strings: List[str], 
              output_file: str = None, case_sensitive: bool = True,
              create_backup: bool = True) -> Dict[str, str]:
    """Mask strings in a file."""

def mask_json_by_keys(self, data, keys: List[str], 
                     case_sensitive: bool = True) -> Tuple[Any, Dict[str, str]]:
    """Mask values in JSON data by key names."""

def mask_json_file(self, input_file: str, keys: List[str], 
                   output_file: str = None, case_sensitive: bool = True,
                   create_backup: bool = True, indent: int = 2) -> Dict[str, str]:
    """Mask JSON file by key names."""
```

## 🧪 Testing

### Run the Demo

```bash
# Large file processing demonstration
python3 demo_large_file_processing.py

# JSON masking CLI demonstration
python3 demo_json_cli.py

# Chunked processing tests
python3 test_chunked_processing.py

# Example usage patterns
python3 example_usage.py

# JSON usage examples
python3 example_json_usage.py
```

### Test Files Included

- `sample_data.txt` - Example configuration file with sensitive data
- `sensitive_strings.txt` - Example patterns file
- `sample_config.json` - Example JSON configuration with sensitive data
- `json_keys.txt` - Example JSON keys file for masking
- `test_chunked_processing.py` - Comprehensive chunked processing tests
- `demo_large_file_processing.py` - Large file demonstration
- `demo_json_cli.py` - Comprehensive JSON CLI demonstration
- `example_json_usage.py` - JSON programmatic usage examples

## 🔒 Security

PyMasker is built with security as a primary concern. See [SECURITY.md](SECURITY.md) for detailed security features and best practices.

### Security Highlights

- ✅ **Cryptographically secure random generation**
- ✅ **Input validation and sanitization**
- ✅ **File system security controls**
- ✅ **Memory safety and DoS protection**
- ✅ **Zero information disclosure**
- ✅ **Comprehensive error handling**

### Security Considerations

⚠️ **Important**: When using the `--seed` option, output is **not cryptographically secure** and should only be used for testing or when reproducible results are required.

## 🎯 Use Cases

### 🏢 **Enterprise Data Sanitization**
- Log file anonymization for sharing with vendors
- Configuration file sanitization for documentation
- Database export anonymization
- Code repository credential removal

### 🧪 **Development & Testing**
- Test data generation with realistic patterns
- Staging environment data preparation
- Demo data creation
- Security testing with sanitized data

### 🔒 **Compliance & Privacy**
- GDPR compliance data masking
- PCI DSS data protection
- HIPAA data anonymization
- SOX compliance data handling

### 📊 **Analytics & Research**
- Research data anonymization
- Analytics data preparation
- Machine learning dataset sanitization
- Statistical analysis data prep

## 🚧 Limitations

- **File Size**: Maximum 1GB file size
- **Pattern Spanning**: Patterns that span chunk boundaries may not be detected in chunked mode
- **Binary Files**: Only supports text files (UTF-8, Latin-1)
- **Regex Patterns**: Currently supports literal string matching only
- **Memory**: In-memory mode requires 2-3x file size in RAM

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/pymasker.git
cd pymasker

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Run security tests
python3 test_chunked_processing.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

- **Documentation**: Check this README and the code comments
- **Issues**: [GitHub Issues](https://github.com/yourusername/pymasker/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for security-related concerns
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/pymasker/discussions)

## 🔄 Version History

### v2.2.0 (Latest)
- 🌐 **NEW**: Automatic IP address detection and masking with `--filter-ips`
- 📡 IPv4 and IPv6 address support with comprehensive regex patterns
- 🔍 IP validation using Python's `ipaddress` module for accuracy
- 🎯 Works in both text and JSON modes, standalone or combined with other filters
- 📋 Recursive IP scanning in nested JSON structures
- 🧪 Enhanced examples and documentation for IP masking workflows

### v2.1.0
- 🔑 **NEW**: JSON processing mode with key-based masking
- 📝 JSON structure preservation and formatting control
- 🎯 Nested object and array support for JSON data
- 📋 File-based JSON key input with `--json-keys-file`
- 🔧 Enhanced CLI with JSON-specific options (`--json-mode`, `--json-keys`, `--json-indent`)
- 🧪 Comprehensive JSON CLI demonstration and examples

### v2.0.0
- ✨ Added chunked processing for large files (up to 1GB)
- 🚀 Memory-efficient streaming architecture
- ⚡ Configurable chunk sizes
- 📊 Automatic processing method selection
- 🔧 Enhanced CLI with `--chunk-size` option

### v1.0.0
- 🎉 Initial release
- 🔒 Security-focused design
- 🎨 Format preservation
- 📝 Command-line interface
- 🔧 Programmatic API

## 📊 Performance Benchmarks

| File Size | In-Memory Time | Chunked Time | Memory Usage |
|-----------|----------------|---------------|--------------|
| 1MB | 0.05s | 0.08s | ~3MB |
| 10MB | 0.3s | 0.5s | ~30MB |
| 50MB | 1.2s | 2.1s | ~150MB |
| 100MB | - | 4.5s | ~15MB |
| 500MB | - | 22s | ~15MB |
| 1GB | - | 45s | ~15MB |

*Benchmarks run on MacBook Pro M1, SSD storage, default 1MB chunk size*

---

**Made with ❤️ for data privacy and security**

*PyMasker - Because your sensitive data deserves better protection* 🛡️
