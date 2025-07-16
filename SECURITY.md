# Security Best Practices - String Masker

## Overview

This document outlines the security measures implemented in the String Masker tool to ensure safe and secure operation when handling sensitive data.

## Security Features Implemented

### 1. Cryptographically Secure Random Number Generation

**Issue**: Using predictable random numbers for masking could allow attackers to reverse-engineer masked data.

**Solution**: 
- Uses Python's `secrets` module by default for cryptographically secure random generation
- Only falls back to predictable `random` module when explicitly requested with `--seed` parameter
- Warns users when using predictable seeds that output will not be cryptographically secure

```python
# Secure by default
self.random_func = secrets.choice

# Predictable only when explicitly requested
if seed is not None:
    import random
    random.seed(seed)
    self.random_func = random.choice
```

### 2. File System Security

**Issues**: Path traversal attacks, symlink attacks, unauthorized file access.

**Solutions**:
- All file paths are resolved to absolute paths using `Path.resolve()`
- Validates that inputs are regular files (not directories or special files)
- Checks file permissions and warns about world-readable files
- Sets restrictive permissions (0o600) on output and backup files
- Prevents processing of excessively large files (DoS protection)

```python
# Path validation
input_path = Path(input_file).resolve()
if not input_path.is_file():
    raise ValueError(f"Path is not a regular file: {input_file}")

# Permission check
if file_stat.st_mode & stat.S_IROTH:
    logging.warning(f"Warning: Input file {input_path} is world-readable")

# Secure output permissions
os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
```

### 3. Input Validation and Sanitization

**Issues**: Buffer overflow, memory exhaustion, injection attacks.

**Solutions**:
- File size limits (100MB for input files, 10MB for string files)
- String count limits (1000 command-line strings, 10000 file strings)
- String length limits (1000 characters per string)
- Minimum character set requirements for random generation (10 characters)
- Strict Unicode encoding/decoding with error handling

```python
# Size limits
max_file_size = 100 * 1024 * 1024  # 100MB limit
if file_stat.st_size > max_file_size:
    raise ValueError(f"File too large: {file_stat.st_size} bytes")

# String validation
max_string_length = 1000
if len(s) > max_string_length:
    print(f"Error: String too long (max {max_string_length} chars)")
```

### 4. Encoding Security

**Issues**: Encoding attacks, data corruption, injection through malformed Unicode.

**Solutions**:
- Strict UTF-8 encoding by default with `errors='strict'`
- Explicit fallback to latin-1 with warnings
- Proper error handling for encoding/decoding failures
- No silent data corruption

```python
# Strict encoding
with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
    content = f.read()
```

### 5. Information Disclosure Prevention

**Issues**: Accidental exposure of sensitive data in logs, output, or error messages.

**Solutions**:
- Truncates long strings in mapping output (100 characters max)
- Redacts sensitive mappings in example code
- Careful error message construction to avoid data leakage
- Secure logging practices

```python
# Safe output display
orig_display = original[:100] + '...' if len(original) > 100 else original
repl_display = replacement[:100] + '...' if len(replacement) > 100 else replacement
```

### 6. Error Handling Security

**Issues**: Information leakage through error messages, application crashes.

**Solutions**:
- Comprehensive exception handling with appropriate error types
- Safe error messages that don't expose internal details
- Graceful degradation on errors
- Proper cleanup on failure

```python
try:
    # File operations
except (OSError, IOError, UnicodeEncodeError) as e:
    raise RuntimeError(f"Failed to write output file: {e}")
```

### 7. Backup Security

**Issues**: Backup files with weak permissions could expose original data.

**Solutions**:
- Backup files created with restrictive permissions (0o600)
- Proper error handling for backup creation
- User control over backup creation

```python
# Secure backup creation
shutil.copy2(input_path, backup_path)
os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
```

## Security Considerations for Users

### 1. File Permissions
- Ensure input files have appropriate permissions before processing
- Be aware that backup and output files will have restrictive permissions (owner-only)
- Consider the security implications of file locations

### 2. Predictable Seeds
- Only use `--seed` parameter for testing or when reproducibility is required
- Be aware that seeded output is not cryptographically secure
- For production masking, avoid using seeds

### 3. String Patterns
- Be mindful of what strings you're masking - overly broad patterns could affect functionality
- Test masking patterns on non-sensitive data first
- Consider case-sensitivity implications for your use case

### 4. Output Handling
- Masked output still contains structure that might be analyzable
- Consider additional obfuscation for highly sensitive data
- Properly dispose of backup files when no longer needed

## Security Testing

The following security aspects have been considered and tested:

1. **Path Traversal**: Tested with paths like `../../../etc/passwd`
2. **Large Files**: Tested with files exceeding size limits
3. **Unicode Attacks**: Tested with malformed Unicode sequences
4. **Symlink Attacks**: Verified symlinks are resolved safely
5. **Permission Escalation**: Verified restrictive file permissions
6. **Memory Exhaustion**: Limited input sizes prevent DoS
7. **Regex Injection**: Uses `re.escape()` for user input

## Reporting Security Issues

If you discover a security vulnerability in this tool, please:

1. Do not create a public issue
2. Contact the maintainer privately
3. Provide detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## Security Checklist for Contributors

When modifying this code, ensure:

- [ ] No use of `eval()` or `exec()`
- [ ] All file operations use absolute paths
- [ ] Input validation for all user-provided data
- [ ] Proper exception handling without information leakage
- [ ] Cryptographically secure random generation (when appropriate)
- [ ] Restrictive file permissions on output
- [ ] No logging of sensitive data
- [ ] Proper encoding handling
- [ ] Resource limits to prevent DoS
- [ ] Safe string operations (no format string vulnerabilities)

## Version History

- v1.0: Initial implementation with comprehensive security measures
