#!/usr/bin/env python3
"""
Advanced String Masker

This script accepts a list of strings and finds matching strings from a file,
then replaces them with random strings (masking) while keeping the formatting
of the original text.

Features:
- Case-sensitive and case-insensitive matching
- Preserves original formatting (length, case pattern)
- Configurable random string generation
- Multiple replacement strategies
- Backup file creation
- Detailed logging

Usage:
    python string_masker.py --file input.txt --strings "secret" "password" "token"
    python string_masker.py --file input.txt --strings-file patterns.txt --output masked.txt
"""

import argparse
import secrets
import string
import re
import os
import shutil
from typing import List, Dict, Tuple, Iterator, Optional, Any, Union, Set
import logging
from pathlib import Path
import sys
import stat
import tempfile
import mmap
import json
import copy
import ipaddress


class StringMasker:
    """Advanced string masking utility with formatting preservation."""
    
    def __init__(self, preserve_case=True, preserve_length=True, 
                 random_chars=None, seed=None, chunk_size=1024*1024):
        """
        Initialize the StringMasker.
        
        Args:
            preserve_case (bool): Preserve original case pattern
            preserve_length (bool): Preserve original string length
            random_chars (str): Characters to use for random generation
            seed (int): Random seed for reproducible results
            chunk_size (int): Size of chunks for processing large files
        """
        self.preserve_case = preserve_case
        self.preserve_length = preserve_length
        self.random_chars = random_chars or string.ascii_letters + string.digits
        self.replacement_cache = {}
        self.chunk_size = chunk_size
        
        # Use cryptographically secure random by default
        self.use_secure_random = seed is None
        if seed is not None:
            # Only use predictable random when explicitly requested with seed
            import random
            random.seed(seed)
            self.random_func = random.choice
        else:
            # Use cryptographically secure random
            self.random_func = secrets.choice
    
    def find_ip_addresses(self, text: str) -> Set[str]:
        """
        Find all IPv4 and IPv6 addresses in the given text.
        
        Args:
            text (str): Text to scan for IP addresses
            
        Returns:
            Set[str]: Set of unique IP addresses found
        """
        ip_addresses = set()
        
        # IPv4 regex pattern - matches valid IPv4 addresses (0-255 for each octet)
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # IPv6 regex pattern - comprehensive pattern for various IPv6 formats
        ipv6_pattern = r'''\b(?:
            # Standard IPv6 (8 groups of 4 hex digits)
            (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|
            # IPv6 with :: compression (various positions)
            (?:[0-9a-fA-F]{1,4}:){1,7}:|
            (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|
            (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|
            (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|
            (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|
            [0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|
            :(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|
            # IPv6 with embedded IPv4
            (?:[0-9a-fA-F]{1,4}:){6}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|
            ::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|
            (?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
        )\b'''
        
        # Find IPv4 addresses
        ipv4_matches = re.finditer(ipv4_pattern, text)
        for match in ipv4_matches:
            ip = match.group()
            # Validate the IP address using ipaddress module
            try:
                ipaddress.IPv4Address(ip)
                ip_addresses.add(ip)
            except ipaddress.AddressValueError:
                # Skip invalid IP addresses
                continue
        
        # Find IPv6 addresses
        ipv6_matches = re.finditer(ipv6_pattern, text, re.VERBOSE | re.IGNORECASE)
        for match in ipv6_matches:
            ip = match.group()
            # Validate the IP address using ipaddress module
            try:
                # Normalize IPv6 address (handles compression, case, etc.)
                normalized_ip = str(ipaddress.IPv6Address(ip))
                ip_addresses.add(ip)  # Keep original format for masking
            except ipaddress.AddressValueError:
                # Skip invalid IP addresses
                continue
        
        return ip_addresses
    
    def find_ip_addresses_in_json(self, json_data: Union[str, Dict, List]) -> Set[str]:
        """
        Find all IP addresses in JSON data by scanning all string values.
        
        Args:
            json_data (Union[str, Dict, List]): JSON data to scan
            
        Returns:
            Set[str]: Set of unique IP addresses found
        """
        # Parse JSON if it's a string
        if isinstance(json_data, str):
            try:
                parsed_data = json.loads(json_data)
            except json.JSONDecodeError:
                # If it's not valid JSON, treat as regular text
                return self.find_ip_addresses(json_data)
        else:
            parsed_data = json_data
        
        ip_addresses = set()
        
        def scan_recursive(obj: Any) -> None:
            """Recursively scan JSON structure for IP addresses."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    # Scan key names for IPs
                    if isinstance(key, str):
                        ip_addresses.update(self.find_ip_addresses(key))
                    scan_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    scan_recursive(item)
            elif isinstance(obj, str):
                # Scan string values for IPs
                ip_addresses.update(self.find_ip_addresses(obj))
            # Skip other types (numbers, booleans, null)
        
        scan_recursive(parsed_data)
        return ip_addresses
    
    def _generate_random_string(self, length: int, case_pattern: str = None) -> str:
        """
        Generate a random string with optional case pattern preservation.
        
        Args:
            length (int): Length of the string to generate
            case_pattern (str): Original string to preserve case pattern from
            
        Returns:
            str: Generated random string
        """
        if not self.preserve_length:
            # Generate random length between 3 and original length + 3
            if self.use_secure_random:
                length = secrets.randbelow(max(1, length + 6 - max(3, length - 2))) + max(3, length - 2)
            else:
                import random
                length = random.randint(max(3, length - 2), length + 3)
        
        if self.preserve_case and case_pattern:
            result = []
            for i, char in enumerate(case_pattern):
                if i >= length:
                    break
                if char.isupper():
                    result.append(self.random_func(self.random_chars).upper())
                elif char.islower():
                    result.append(self.random_func(self.random_chars).lower())
                elif char.isdigit():
                    result.append(self.random_func(string.digits))
                else:
                    result.append(self.random_func(self.random_chars))
            
            # Fill remaining length if needed
            while len(result) < length:
                result.append(self.random_func(self.random_chars))
            
            return ''.join(result)
        else:
            return ''.join(self.random_func(self.random_chars) for _ in range(length))
    
    def _get_replacement(self, original: str) -> str:
        """
        Get or generate a replacement string for the original.
        Uses caching to ensure consistent replacements.
        
        Args:
            original (str): Original string to replace
            
        Returns:
            str: Replacement string
        """
        # Use lowercase for cache key to handle case-insensitive matching
        cache_key = original.lower()
        
        if cache_key in self.replacement_cache:
            # Apply case pattern to cached replacement
            cached = self.replacement_cache[cache_key]
            if self.preserve_case:
                return self._apply_case_pattern(cached, original)
            return cached
        
        # Generate new replacement
        replacement = self._generate_random_string(len(original), original)
        self.replacement_cache[cache_key] = replacement.lower()
        
        if self.preserve_case:
            return self._apply_case_pattern(replacement, original)
        return replacement
    
    def _apply_case_pattern(self, replacement: str, original: str) -> str:
        """Apply the case pattern from original to replacement string."""
        result = []
        for i, (r_char, o_char) in enumerate(zip(replacement, original)):
            if o_char.isupper():
                result.append(r_char.upper())
            elif o_char.islower():
                result.append(r_char.lower())
            else:
                result.append(r_char)
        return ''.join(result)
    
    def mask_strings_in_text(self, text: str, target_strings: List[str], 
                           case_sensitive: bool = True) -> Tuple[str, Dict[str, str]]:
        """
        Mask target strings in the given text.
        
        Args:
            text (str): Input text to process
            target_strings (List[str]): Strings to find and replace
            case_sensitive (bool): Whether matching should be case-sensitive
            
        Returns:
            Tuple[str, Dict[str, str]]: (masked_text, replacement_mapping)
        """
        masked_text = text
        replacement_mapping = {}
        
        # Sort strings by length (descending) to handle overlapping matches
        sorted_strings = sorted(target_strings, key=len, reverse=True)
        
        for target in sorted_strings:
            if not target.strip():  # Skip empty strings
                continue
            
            # Create regex pattern
            if case_sensitive:
                pattern = re.escape(target)
            else:
                pattern = re.escape(target)
                flags = re.IGNORECASE
            
            # Find all matches
            matches = list(re.finditer(pattern, masked_text, 
                                     flags=re.IGNORECASE if not case_sensitive else 0))
            
            if matches:
                # Process matches in reverse order to maintain positions
                for match in reversed(matches):
                    original_match = match.group()
                    replacement = self._get_replacement(original_match)
                    
                    # Store mapping
                    if original_match not in replacement_mapping:
                        replacement_mapping[original_match] = replacement
                    
                    # Replace in text
                    start, end = match.span()
                    masked_text = masked_text[:start] + replacement + masked_text[end:]
        
        return masked_text, replacement_mapping
    
    def mask_json_by_keys(self, json_data: Union[str, Dict, List], target_keys: List[str], 
                         case_sensitive: bool = True) -> Tuple[Union[Dict, List], Dict[str, str]]:
        """
        Mask values in JSON data for specific keys.
        
        Args:
            json_data (Union[str, Dict, List]): JSON data as string or parsed object
            target_keys (List[str]): Keys whose values should be masked
            case_sensitive (bool): Whether key matching should be case-sensitive
            
        Returns:
            Tuple[Union[Dict, List], Dict[str, str]]: (masked_json, replacement_mapping)
        """
        # Parse JSON if it's a string
        if isinstance(json_data, str):
            try:
                parsed_data = json.loads(json_data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")
        else:
            parsed_data = copy.deepcopy(json_data)
        
        replacement_mapping = {}
        
        # Normalize target keys for case-insensitive matching
        if not case_sensitive:
            target_keys_lower = [key.lower() for key in target_keys]
        else:
            target_keys_lower = target_keys
        
        def mask_recursive(obj: Any, path: str = "") -> Any:
            if isinstance(obj, dict):
                masked_dict = {}
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if this key should be masked
                    key_matches = False
                    if case_sensitive:
                        key_matches = key in target_keys
                    else:
                        key_matches = key.lower() in target_keys_lower
                    
                    if key_matches and isinstance(value, str):
                        # Mask the string value
                        if value.strip():  # Only mask non-empty strings
                            masked_value = self._get_replacement(value)
                            replacement_mapping[f"{current_path}: {value}"] = masked_value
                            masked_dict[key] = masked_value
                        else:
                            masked_dict[key] = value
                    elif key_matches and isinstance(value, (int, float)):
                        # Mask numeric values by converting to string and back
                        original_str = str(value)
                        masked_str = self._get_replacement(original_str)
                        replacement_mapping[f"{current_path}: {value}"] = masked_str
                        
                        # Try to convert back to original type
                        try:
                            if isinstance(value, int):
                                # Generate random integer of similar magnitude
                                if self.use_secure_random:
                                    masked_dict[key] = secrets.randbelow(10 ** len(str(abs(value)))) 
                                else:
                                    import random
                                    masked_dict[key] = random.randint(0, 10 ** len(str(abs(value))) - 1)
                            else:
                                # Generate random float
                                if self.use_secure_random:
                                    masked_dict[key] = round(secrets.randbelow(10000) / 100.0, 2)
                                else:
                                    import random
                                    masked_dict[key] = round(random.uniform(0, 100), 2)
                        except:
                            # Fallback to string replacement
                            masked_dict[key] = masked_str
                    else:
                        # Recursively process nested structures
                        masked_dict[key] = mask_recursive(value, current_path)
                        
                return masked_dict
                
            elif isinstance(obj, list):
                return [mask_recursive(item, f"{path}[{i}]") for i, item in enumerate(obj)]
            else:
                return obj
        
        masked_data = mask_recursive(parsed_data)
        return masked_data, replacement_mapping
    
    def mask_json_file(self, input_file: str, target_keys: List[str], 
                      output_file: str = None, case_sensitive: bool = True,
                      create_backup: bool = True, indent: Optional[int] = 2) -> Dict[str, str]:
        """
        Mask JSON keys in a file.
        
        Args:
            input_file (str): Path to input JSON file
            target_keys (List[str]): Keys whose values should be masked
            output_file (str): Path to output file (default: overwrite input)
            case_sensitive (bool): Whether key matching should be case-sensitive
            create_backup (bool): Create backup of original file
            indent (Optional[int]): JSON indentation for output (None for compact)
            
        Returns:
            Dict[str, str]: Replacement mapping
        """
        input_path = Path(input_file).resolve()
        
        # Security: Validate input path
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if not input_path.is_file():
            raise ValueError(f"Path is not a regular file: {input_file}")
        
        # Security: Check file permissions
        file_stat = input_path.stat()
        if file_stat.st_mode & stat.S_IROTH:
            logging.warning(f"Warning: Input file {input_path} is world-readable")
        
        # Security: Check file size to prevent DoS
        max_file_size = 1024 * 1024 * 1024  # 1GB limit
        if file_stat.st_size > max_file_size:
            raise ValueError(f"File too large: {file_stat.st_size} bytes (max: {max_file_size})")
        
        # Read and parse JSON file
        try:
            with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
                json_content = f.read()
        except UnicodeDecodeError:
            logging.warning(f"UTF-8 decoding failed for {input_path}, trying latin-1")
            try:
                with open(input_path, 'r', encoding='latin-1', errors='strict') as f:
                    json_content = f.read()
            except UnicodeDecodeError as e:
                raise ValueError(f"Unable to decode file {input_path}: {e}")
        
        # Parse JSON
        try:
            json_data = json.loads(json_content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in file {input_path}: {e}")
        
        # Create backup if requested
        if create_backup:
            backup_path = input_path.with_suffix(input_path.suffix + '.backup')
            try:
                shutil.copy2(input_path, backup_path)
                os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)
                logging.info(f"Backup created: {backup_path}")
            except (OSError, IOError) as e:
                raise RuntimeError(f"Failed to create backup: {e}")
        
        # Mask JSON data
        masked_data, replacement_mapping = self.mask_json_by_keys(
            json_data, target_keys, case_sensitive
        )
        
        # Determine output file
        output_path = Path(output_file).resolve() if output_file else input_path
        
        # Security: Validate output path
        if output_path.exists() and not output_path.is_file():
            raise ValueError(f"Output path exists but is not a regular file: {output_path}")
        
        # Write masked JSON
        try:
            with open(output_path, 'w', encoding='utf-8', errors='strict') as f:
                json.dump(masked_data, f, indent=indent, ensure_ascii=False)
            
            # Security: Set restrictive permissions on output file
            os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except (OSError, IOError, UnicodeEncodeError) as e:
            raise RuntimeError(f"Failed to write output file: {e}")
        
        logging.info(f"Masked JSON written to: {output_path}")
        return replacement_mapping
    
    def _calculate_overlap_size(self, target_strings: List[str]) -> int:
        """Calculate the overlap size needed to handle patterns spanning chunks."""
        if not target_strings:
            return 0
        # Use the length of the longest target string as overlap
        max_length = max(len(s) for s in target_strings if s.strip())
        # Add some buffer for safety
        return min(max_length * 2, 10000)  # Cap at 10KB overlap
    
    def _process_chunk_with_overlap(self, chunk: str, overlap_buffer: str, 
                                   target_strings: List[str], case_sensitive: bool, is_last_chunk: bool = False) -> Tuple[str, str]:
        """Process a chunk with overlap handling."""
        # Combine overlap buffer with current chunk
        combined_text = overlap_buffer + chunk
        
        if not combined_text:
            return "", ""
        
        # Mask the combined text
        masked_combined, _ = self.mask_strings_in_text(combined_text, target_strings, case_sensitive)
        
        # Calculate how much of the masked text corresponds to the original overlap
        overlap_len = len(overlap_buffer)
        
        if is_last_chunk:
            # For the last chunk, return everything after the overlap
            if overlap_len > 0:
                return masked_combined[overlap_len:], ""
            else:
                return masked_combined, ""
        
        if overlap_len == 0:
            # No overlap, return most of the chunk but keep some for next overlap
            if len(masked_combined) > self.overlap_size:
                return masked_combined[:-self.overlap_size], combined_text[-self.overlap_size:]
            else:
                return masked_combined, ""
        else:
            # There was overlap, return only the new portion but keep overlap for next chunk
            chunk_start = overlap_len
            if len(masked_combined) > chunk_start + self.overlap_size:
                # Return the new content minus the overlap for next chunk
                content_end = len(masked_combined) - self.overlap_size
                new_content = masked_combined[chunk_start:content_end]
                # The new overlap should be from the original combined text, not masked
                new_overlap = combined_text[-self.overlap_size:]
                return new_content, new_overlap
            else:
                # Chunk is smaller than overlap size
                new_content = masked_combined[chunk_start:]
                return new_content, ""
    
    def mask_file_chunked(self, input_file: str, target_strings: List[str], 
                         output_file: str = None, case_sensitive: bool = True,
                         create_backup: bool = True) -> Dict[str, str]:
        """Mask strings in a file using chunked processing for memory efficiency."""
        input_path = Path(input_file).resolve()
        
        # Security: Validate input path
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if not input_path.is_file():
            raise ValueError(f"Path is not a regular file: {input_file}")
        
        # Security: Check file permissions
        file_stat = input_path.stat()
        if file_stat.st_mode & stat.S_IROTH:
            logging.warning(f"Warning: Input file {input_path} is world-readable")
        
        # Security: Check file size to prevent DoS
        max_file_size = 1024 * 1024 * 1024  # 1GB limit
        if file_stat.st_size > max_file_size:
            raise ValueError(f"File too large: {file_stat.st_size} bytes (max: {max_file_size})")
        
        # Calculate overlap size needed
        self.overlap_size = self._calculate_overlap_size(target_strings)
        
        # Create backup if requested
        if create_backup:
            backup_path = input_path.with_suffix(input_path.suffix + '.backup')
            try:
                shutil.copy2(input_path, backup_path)
                os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)
                logging.info(f"Backup created: {backup_path}")
            except (OSError, IOError) as e:
                raise RuntimeError(f"Failed to create backup: {e}")
        
        # Process file in chunks with overlap handling
        temp_fd, temp_path = tempfile.mkstemp()
        os.close(temp_fd)
        
        try:
            replacement_mapping = {}
            overlap_buffer = ""
            
            with open(input_path, 'r', encoding='utf-8', errors='strict') as input_file, \
                 open(temp_path, 'w', encoding='utf-8', errors='strict') as temp_file:
                
                chunk_count = 0
                while True:
                    chunk = input_file.read(self.chunk_size)
                    chunk_count += 1
                    
                    if not chunk:
                        # Process any remaining overlap buffer
                        if overlap_buffer:
                            final_masked, _ = self._process_chunk_with_overlap(
                                "", overlap_buffer, target_strings, case_sensitive, is_last_chunk=True
                            )
                            temp_file.write(final_masked)
                        break
                    
                    # Check if this is the last chunk by trying to peek ahead
                    next_chunk_start = input_file.tell()
                    peek_chunk = input_file.read(1)
                    is_last = not bool(peek_chunk)
                    input_file.seek(next_chunk_start)  # Reset position
                    
                    # Process chunk with overlap
                    masked_content, new_overlap = self._process_chunk_with_overlap(
                        chunk, overlap_buffer, target_strings, case_sensitive, is_last_chunk=is_last
                    )
                    
                    # Write the processed content
                    temp_file.write(masked_content)
                    
                    # Update overlap buffer for next iteration
                    overlap_buffer = new_overlap
                    
                    # Update replacement mapping (this is approximate since we're processing in chunks)
                    # The actual replacements are consistent due to caching
                    replacement_mapping.update(self.replacement_cache)
                    
        except UnicodeDecodeError:
            logging.warning(f"UTF-8 decoding failed for {input_path}, trying latin-1")
            try:
                replacement_mapping = {}
                overlap_buffer = ""
                
                with open(input_path, 'r', encoding='latin-1', errors='strict') as input_file, \
                     open(temp_path, 'w', encoding='latin-1', errors='strict') as temp_file:
                    
                    chunk_count = 0
                    while True:
                        chunk = input_file.read(self.chunk_size)
                        chunk_count += 1
                        
                        if not chunk:
                            if overlap_buffer:
                                final_masked, _ = self._process_chunk_with_overlap(
                                    "", overlap_buffer, target_strings, case_sensitive, is_last_chunk=True
                                )
                                temp_file.write(final_masked)
                            break
                        
                        # Check if this is the last chunk
                        next_chunk_start = input_file.tell()
                        peek_chunk = input_file.read(1)
                        is_last = not bool(peek_chunk)
                        input_file.seek(next_chunk_start)
                        
                        masked_content, new_overlap = self._process_chunk_with_overlap(
                            chunk, overlap_buffer, target_strings, case_sensitive, is_last_chunk=is_last
                        )
                        
                        temp_file.write(masked_content)
                        overlap_buffer = new_overlap
                        replacement_mapping.update(self.replacement_cache)
                        
            except UnicodeDecodeError as e:
                os.unlink(temp_path)
                raise ValueError(f"Unable to decode file {input_path}: {e}")
        
        # Move temp file to output
        output_path = Path(output_file).resolve() if output_file else input_path
        
        # Security: Validate output path
        if output_path.exists() and not output_path.is_file():
            os.unlink(temp_path)
            raise ValueError(f"Output path exists but is not a regular file: {output_path}")
        
        try:
            shutil.move(temp_path, output_path)
            os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            logging.info(f"Masked content written to: {output_path}")
        except (OSError, IOError) as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise RuntimeError(f"Failed to write output file: {e}")
        
        return replacement_mapping
    
    def mask_file(self, input_file: str, target_strings: List[str], 
                  output_file: str = None, case_sensitive: bool = True,
                  create_backup: bool = True) -> Dict[str, str]:
        """
        Mask strings in a file.
        
        Args:
            input_file (str): Path to input file
            target_strings (List[str]): Strings to find and replace
            output_file (str): Path to output file (default: overwrite input)
            case_sensitive (bool): Whether matching should be case-sensitive
            create_backup (bool): Create backup of original file
            
        Returns:
            Dict[str, str]: Replacement mapping
        """
        input_path = Path(input_file).resolve()  # Resolve to absolute path
        
        # Security: Validate input path
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Security: Ensure it's a regular file, not a directory or special file
        if not input_path.is_file():
            raise ValueError(f"Path is not a regular file: {input_file}")
        
        # Security: Check file permissions
        file_stat = input_path.stat()
        if file_stat.st_mode & stat.S_IROTH:
            logging.warning(f"Warning: Input file {input_path} is world-readable")
        
        # Security: Check file size to prevent DoS
        max_file_size = 1024 * 1024 * 1024  # 1GB limit
        if file_stat.st_size > max_file_size:
            raise ValueError(f"File too large: {file_stat.st_size} bytes (max: {max_file_size})")
        
        # For small files, use the original in-memory approach
        if file_stat.st_size <= 50 * 1024 * 1024:  # 50MB threshold
            logging.info(f"Using in-memory processing for file size: {file_stat.st_size} bytes")
            return self._mask_file_in_memory(input_path, target_strings, output_file, case_sensitive, create_backup)
        else:
            # For large files, use chunked processing
            logging.info(f"Using chunked processing for file size: {file_stat.st_size} bytes")
            return self.mask_file_chunked(input_file, target_strings, output_file, case_sensitive, create_backup)
    
    def _mask_file_in_memory(self, input_path: Path, target_strings: List[str], 
                            output_file: str = None, case_sensitive: bool = True,
                            create_backup: bool = True) -> Dict[str, str]:
        """Original in-memory processing for smaller files."""
        # Read input file securely
        try:
            with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Try with different encoding but be explicit about potential issues
            logging.warning(f"UTF-8 decoding failed for {input_path}, trying latin-1")
            try:
                with open(input_path, 'r', encoding='latin-1', errors='strict') as f:
                    content = f.read()
            except UnicodeDecodeError as e:
                raise ValueError(f"Unable to decode file {input_path}: {e}")
        
        # Create backup if requested
        if create_backup:
            backup_path = input_path.with_suffix(input_path.suffix + '.backup')
            try:
                shutil.copy2(input_path, backup_path)
                # Security: Set restrictive permissions on backup
                os.chmod(backup_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
                logging.info(f"Backup created: {backup_path}")
            except (OSError, IOError) as e:
                raise RuntimeError(f"Failed to create backup: {e}")
        
        # Mask content
        masked_content, replacement_mapping = self.mask_strings_in_text(
            content, target_strings, case_sensitive
        )
        
        # Determine output file
        output_path = Path(output_file).resolve() if output_file else input_path
        
        # Security: Validate output path
        if output_path.exists() and not output_path.is_file():
            raise ValueError(f"Output path exists but is not a regular file: {output_path}")
        
        # Write output securely
        try:
            with open(output_path, 'w', encoding='utf-8', errors='strict') as f:
                f.write(masked_content)
            
            # Security: Set restrictive permissions on output file
            os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except (OSError, IOError, UnicodeEncodeError) as e:
            raise RuntimeError(f"Failed to write output file: {e}")
        
        logging.info(f"Masked content written to: {output_path}")
        return replacement_mapping

def load_strings_from_file(file_path: str) -> List[str]:
    """Load target strings from a file (one per line)."""
    input_path = Path(file_path).resolve()
    
    # Security: Validate input path
    if not input_path.exists():
        raise FileNotFoundError(f"Strings file not found: {file_path}")
    
    if not input_path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")
    
    # Security: Check file size
    max_file_size = 10 * 1024 * 1024  # 10MB limit for strings file
    file_stat = input_path.stat()
    if file_stat.st_size > max_file_size:
        raise ValueError(f"Strings file too large: {file_stat.st_size} bytes (max: {max_file_size})")
    
    try:
        with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
            lines = [line.strip() for line in f if line.strip()]
            
        # Security: Limit number of strings
        max_strings = 10000
        if len(lines) > max_strings:
            raise ValueError(f"Too many strings in file: {len(lines)} (max: {max_strings})")
            
        return lines
    except UnicodeDecodeError as e:
        raise ValueError(f"Unable to decode strings file {file_path}: {e}")


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Mask strings in files while preserving formatting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Text mode: Mask specific strings
  python string_masker.py --file data.txt --strings "password" "secret" "token"
  
  # Text mode: Load strings from file
  python string_masker.py --file data.txt --strings-file patterns.txt
  
  # Text mode: Automatically detect and mask IP addresses
  python string_masker.py --file logfile.txt --filter-ips
  
  # Text mode: Mask strings AND IP addresses
  python string_masker.py --file data.txt --strings "password" --filter-ips
  
  # JSON mode: Mask values for specific keys
  python string_masker.py --json-mode --file config.json --json-keys "password" "api_key" "secret"
  
  # JSON mode: Load keys from file with compact output
  python string_masker.py --json-mode --file data.json --json-keys-file keys.txt --json-indent 0
  
  # JSON mode: Automatically detect and mask IP addresses only
  python string_masker.py --json-mode --file config.json --filter-ips
  
  # JSON mode: Mask specific keys AND any IP addresses found
  python string_masker.py --json-mode --file config.json --json-keys "password" --filter-ips
  
  # Case-insensitive matching with custom output
  python string_masker.py --file input.txt --strings "API_KEY" --output masked.txt --ignore-case
  
  # JSON mode with case-insensitive key matching
  python string_masker.py --json-mode --file config.json --json-keys "Password" "API_Key" --ignore-case
        """
    )
    
    # File arguments
    parser.add_argument('--file', '-f', required=True,
                       help='Input file to process')
    parser.add_argument('--output', '-o',
                       help='Output file (default: overwrite input)')
    
    # Processing mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--json-mode', action='store_true',
                           help='JSON mode: mask values for specific keys')
    
    # String sources (for text mode)
    string_group = parser.add_mutually_exclusive_group()
    string_group.add_argument('--strings', '-s', nargs='+',
                             help='List of strings to mask (text mode)')
    string_group.add_argument('--strings-file', '-sf',
                             help='File containing strings to mask (text mode)')
    
    # JSON key sources (for JSON mode)
    json_group = parser.add_mutually_exclusive_group()
    json_group.add_argument('--json-keys', '-jk', nargs='+',
                           help='List of JSON keys whose values to mask (JSON mode)')
    json_group.add_argument('--json-keys-file', '-jkf',
                           help='File containing JSON keys to mask (JSON mode)')
    
    # Masking options
    parser.add_argument('--ignore-case', '-i', action='store_true',
                       help='Case-insensitive matching')
    parser.add_argument('--no-preserve-case', action='store_true',
                       help='Do not preserve original case pattern')
    parser.add_argument('--no-preserve-length', action='store_true',
                       help='Do not preserve original string length')
    parser.add_argument('--random-chars',
                       default=string.ascii_letters + string.digits,
                       help='Characters to use for random generation')
    parser.add_argument('--seed', type=int,
                       help='Random seed for reproducible results')
    parser.add_argument('--chunk-size', type=int, default=1024*1024,
                       help='Chunk size in bytes for processing large files (default: 1MB)')
    
    # JSON-specific options
    parser.add_argument('--json-indent', type=int, default=2,
                       help='JSON indentation level (default: 2, use 0 for compact)')
    
    # IP filtering options
    parser.add_argument('--filter-ips', action='store_true',
                       help='Automatically detect and mask IP addresses (IPv4 and IPv6)')
    
    # Other options
    parser.add_argument('--no-backup', action='store_true',
                       help='Do not create backup file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--show-mapping', action='store_true',
                       help='Show replacement mapping')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    try:
        # Initialize masker for IP detection if needed
        masker = StringMasker(
            preserve_case=not args.no_preserve_case,
            preserve_length=not args.no_preserve_length,
            random_chars=args.random_chars,
            seed=args.seed,
            chunk_size=args.chunk_size
        )
        
        # Determine processing mode and validate arguments
        if args.json_mode:
            # JSON mode - require JSON keys or IP filtering
            if not args.json_keys and not args.json_keys_file and not args.filter_ips:
                print("Error: JSON mode requires --json-keys, --json-keys-file, or --filter-ips")
                return 1
            
            # Load JSON keys
            target_keys = []
            if args.json_keys:
                target_keys = args.json_keys
                # Security: Limit number of command-line keys
                if len(target_keys) > 1000:
                    print("Error: Too many JSON keys provided (max: 1000)")
                    return 1
            elif args.json_keys_file:
                target_keys = load_strings_from_file(args.json_keys_file)
            
            # If IP filtering is enabled, we'll handle it differently for JSON mode
            if args.filter_ips and not target_keys:
                # For JSON mode with only IP filtering, we need to scan the JSON content
                # This will be handled in the processing section
                pass
            elif not target_keys and not args.filter_ips:
                print("Error: No JSON keys provided")
                return 1
            
            # Security: Validate key lengths
            max_key_length = 1000
            for key in target_keys:
                if len(key) > max_key_length:
                    print(f"Error: JSON key too long (max {max_key_length} chars): {key[:50]}...")
                    return 1
        else:
            # Text mode - require strings or IP filtering
            if not args.strings and not args.strings_file and not args.filter_ips:
                print("Error: Text mode requires --strings, --strings-file, or --filter-ips")
                return 1
            
            # Load target strings
            target_strings = []
            if args.strings:
                target_strings = args.strings
                # Security: Limit number of command-line strings
                if len(target_strings) > 1000:
                    print("Error: Too many strings provided (max: 1000)")
                    return 1
            elif args.strings_file:
                target_strings = load_strings_from_file(args.strings_file)
            
            # Add IP addresses to target strings if IP filtering is enabled
            if args.filter_ips:
                # Read the input file to detect IPs
                try:
                    input_path = Path(args.file).resolve()
                    if not input_path.exists():
                        print(f"Error: Input file not found: {args.file}")
                        return 1
                    
                    # Read file content for IP detection
                    try:
                        with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
                            content = f.read()
                    except UnicodeDecodeError:
                        try:
                            with open(input_path, 'r', encoding='latin-1', errors='strict') as f:
                                content = f.read()
                        except UnicodeDecodeError as e:
                            print(f"Error: Unable to decode file {args.file}: {e}")
                            return 1
                    
                    # Detect IP addresses
                    detected_ips = masker.find_ip_addresses(content)
                    if detected_ips:
                        target_strings.extend(list(detected_ips))
                        if args.verbose:
                            print(f"Detected {len(detected_ips)} IP addresses: {', '.join(sorted(detected_ips))}")
                    else:
                        if args.verbose:
                            print("No IP addresses detected in the input file")
                        
                except Exception as e:
                    print(f"Error reading file for IP detection: {e}")
                    return 1
            
            if not target_strings:
                if args.filter_ips:
                    print("No IP addresses found in the input file")
                else:
                    print("Error: No target strings provided")
                return 1
            
            # Security: Validate string lengths
            max_string_length = 1000
            for s in target_strings:
                if len(s) > max_string_length:
                    print(f"Error: String too long (max {max_string_length} chars): {s[:50]}...")
                    return 1
        
        # Security: Validate random_chars
        if len(args.random_chars) < 10:
            print("Error: random_chars must contain at least 10 characters")
            return 1
        
        # Security: Warn about predictable seeds
        if args.seed is not None:
            logging.warning("Using predictable random seed - output will not be cryptographically secure")
        
        # Security: Validate chunk size
        if args.chunk_size < 1024:  # Minimum 1KB
            print("Error: chunk_size must be at least 1024 bytes")
            return 1
        if args.chunk_size > 100 * 1024 * 1024:  # Maximum 100MB
            print("Error: chunk_size must be at most 100MB")
            return 1
        
        
        # Process file based on mode
        if args.json_mode:
            if args.filter_ips and not target_keys:
                # Special handling for JSON mode with only IP filtering
                # Read JSON file and detect IPs, then mask the entire content as text
                try:
                    input_path = Path(args.file).resolve()
                    with open(input_path, 'r', encoding='utf-8', errors='strict') as f:
                        json_content = f.read()
                    
                    # Detect IPs in JSON content
                    detected_ips = masker.find_ip_addresses_in_json(json_content)
                    if detected_ips:
                        detected_ips_list = list(detected_ips)
                        if args.verbose:
                            print(f"Detected {len(detected_ips)} IP addresses in JSON: {', '.join(sorted(detected_ips))}")
                        
                        # Mask the JSON content as text
                        replacement_mapping = masker.mask_file(
                            input_file=args.file,
                            target_strings=detected_ips_list,
                            output_file=args.output,
                            case_sensitive=not args.ignore_case,
                            create_backup=not args.no_backup
                        )
                    else:
                        print("No IP addresses found in the JSON file")
                        replacement_mapping = {}
                except Exception as e:
                    print(f"Error processing JSON file for IP filtering: {e}")
                    return 1
            else:
                # Regular JSON mode processing
                indent = args.json_indent if args.json_indent > 0 else None
                replacement_mapping = masker.mask_json_file(
                    input_file=args.file,
                    target_keys=target_keys,
                    output_file=args.output,
                    case_sensitive=not args.ignore_case,
                    create_backup=not args.no_backup,
                    indent=indent
                )
                
                # If IP filtering is also enabled with JSON keys, detect and mask IPs in the output
                if args.filter_ips and target_keys:
                    # After masking JSON keys, also mask any remaining IPs in the content
                    try:
                        output_path = Path(args.output).resolve() if args.output else Path(args.file).resolve()
                        with open(output_path, 'r', encoding='utf-8', errors='strict') as f:
                            masked_content = f.read()
                        
                        detected_ips = masker.find_ip_addresses(masked_content)
                        if detected_ips:
                            detected_ips_list = list(detected_ips)
                            if args.verbose:
                                print(f"Detected additional {len(detected_ips)} IP addresses: {', '.join(sorted(detected_ips))}")
                            
                            # Mask IPs in the already processed file
                            additional_mapping = masker.mask_file(
                                input_file=str(output_path),
                                target_strings=detected_ips_list,
                                output_file=str(output_path),
                                case_sensitive=not args.ignore_case,
                                create_backup=False  # Already backed up
                            )
                            replacement_mapping.update(additional_mapping)
                    except Exception as e:
                        if args.verbose:
                            print(f"Warning: Could not perform additional IP filtering: {e}")
        else:
            # Text mode processing
            replacement_mapping = masker.mask_file(
                input_file=args.file,
                target_strings=target_strings,
                output_file=args.output,
                case_sensitive=not args.ignore_case,
                create_backup=not args.no_backup
            )
        
        # Show results
        if replacement_mapping:
            print(f"Successfully masked {len(replacement_mapping)} unique strings")
            
            if args.show_mapping:
                print("\nReplacement mapping:")
                for original, replacement in replacement_mapping.items():
                    # Security: Truncate very long strings in output
                    orig_display = original[:100] + '...' if len(original) > 100 else original
                    repl_display = replacement[:100] + '...' if len(replacement) > 100 else replacement
                    print(f"  '{orig_display}' -> '{repl_display}'")
        else:
            print("No matching strings found to mask")
        
        return 0
        
    except Exception as e:
        logging.error(f"Error: {e}")
        return 1


if __name__ == '__main__':
    exit(main())
