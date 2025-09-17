#!/usr/bin/env python3
# encoding: UTF-8

"""
Test script for efficient file size detection (Issue #783 improvement)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.utils import settings
from src.core.injections.controller import checks
from src.core.injections.blind.techniques.time_based import tb_payloads

def test_filename_extraction():
    """Test the filename extraction function"""
    print("Testing filename extraction...")
    
    # Test Unix commands
    settings.TARGET_OS = "unix"
    test_cases = [
        ("cat /etc/passwd", "/etc/passwd"),
        ("cat /tmp/test.txt", "/tmp/test.txt"),
        ("head -n 10 /var/log/syslog", "/var/log/syslog"),
        ("tail /home/user/file.log", "/home/user/file.log"),
    ]
    
    for cmd, expected in test_cases:
        result = checks.extract_filename_from_cmd(cmd)
        if result == expected:
            print(f"  ✓ '{cmd}' -> '{result}'")
        else:
            print(f"  ✗ '{cmd}' -> '{result}' (expected: '{expected}')")
    
    # Test Windows commands
    settings.TARGET_OS = settings.OS.WINDOWS
    test_cases = [
        ("type C:\\Windows\\System32\\drivers\\etc\\hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ("type config.ini", "config.ini"),
    ]
    
    for cmd, expected in test_cases:
        result = checks.extract_filename_from_cmd(cmd)
        if result == expected:
            print(f"  ✓ '{cmd}' -> '{result}'")
        else:
            print(f"  ✗ '{cmd}' -> '{result}' (expected: '{expected}')")

def test_file_operation_detection():
    """Test the file operation detection function"""
    print("\nTesting file operation detection...")
    
    # Test Unix
    settings.TARGET_OS = "unix"
    test_cases = [
        ("cat /etc/passwd", True),
        ("head /var/log/messages", True), 
        ("tail -f /var/log/syslog", True),
        ("ls -la /tmp", False),
        ("ps aux", False),
        ("whoami", False),
    ]
    
    for cmd, expected in test_cases:
        result = checks.is_file_read_operation(cmd)
        if result == expected:
            print(f"  ✓ '{cmd}' -> {result}")
        else:
            print(f"  ✗ '{cmd}' -> {result} (expected: {expected})")

def test_efficient_detection_conditions():
    """Test when efficient detection should be used"""
    print("\nTesting efficient detection conditions...")
    
    # Mock settings
    settings.TIME_RELATED_ATTACK = True
    
    test_cases = [
        ("cat /etc/passwd", True),
        ("ps aux", False),
        ("whoami", False),
    ]
    
    for cmd, expected in test_cases:
        result = checks.should_use_efficient_file_detection(cmd)
        if result == expected:
            print(f"  ✓ '{cmd}' -> {result}")
        else:
            print(f"  ✗ '{cmd}' -> {result} (expected: {expected})")
    
    # Test when TIME_RELATED_ATTACK is False
    settings.TIME_RELATED_ATTACK = False
    result = checks.should_use_efficient_file_detection("cat /etc/passwd")
    if result == False:
        print(f"  ✓ TIME_RELATED_ATTACK=False -> {result}")
    else:
        print(f"  ✗ TIME_RELATED_ATTACK=False -> {result} (expected: False)")

def test_payload_generation():
    """Test payload generation for new functions"""
    print("\nTesting payload generation...")
    
    # Test file existence check payload
    separator = ";"
    filename = "/etc/passwd"
    timesec = 1
    http_request_method = "GET"
    
    try:
        payload = tb_payloads.file_exists_check(filename, separator, timesec, http_request_method)
        if payload and ("test -f" in payload or "[ -f" in payload) and filename in payload:
            print(f"  ✓ file_exists_check payload generated")
        else:
            print(f"  ✗ file_exists_check payload incorrect: {payload}")
    except Exception as e:
        print(f"  ✗ file_exists_check failed: {e}")
    
    # Test file not empty check payload
    try:
        payload = tb_payloads.file_not_empty_check(filename, separator, timesec, http_request_method)
        if payload and "[ -s" in payload and filename in payload:
            print(f"  ✓ file_not_empty_check payload generated")
        else:
            print(f"  ✗ file_not_empty_check payload incorrect: {payload}")
    except Exception as e:
        print(f"  ✗ file_not_empty_check failed: {e}")
    
    # Test stat output length payload
    try:
        payload = tb_payloads.get_stat_output_length(filename, 4, separator, timesec, http_request_method)
        if payload and "stat --printf" in payload and filename in payload:
            print(f"  ✓ get_stat_output_length payload generated")
        else:
            print(f"  ✗ get_stat_output_length payload incorrect: {payload}")
    except Exception as e:
        print(f"  ✗ get_stat_output_length failed: {e}")
    
    # Test file size digit extraction payload
    try:
        payload = tb_payloads.get_file_size_digit(filename, 1, 3, separator, timesec, http_request_method)
        if payload and "stat --printf" in payload and filename in payload:
            print(f"  ✓ get_file_size_digit payload generated")
        else:
            print(f"  ✗ get_file_size_digit payload incorrect: {payload}")
    except Exception as e:
        print(f"  ✗ get_file_size_digit failed: {e}")

def main():
    """Run all tests"""
    print("=" * 60)
    print("Efficient File Size Detection Tests (Issue #783)")
    print("=" * 60)
    
    # Initialize basic settings
    settings.TARGET_OS = "unix"
    settings.TIME_RELATED_ATTACK = True
    settings.FILE_READ = "cat "
    settings.WIN_FILE_READ = "type "
    settings.VERBOSITY_LEVEL = 0
    settings.CUSTOM_INJECTION_MARKER = False
    
    # Mock other required settings
    settings.RANDOM_VAR_GENERATOR = "TMP"
    settings.CMD_SUB_PREFIX = "$("
    settings.CMD_SUB_SUFFIX = ")"
    settings.SINGLE_WHITESPACE = " "
    
    # Run tests
    test_filename_extraction()
    test_file_operation_detection()
    test_efficient_detection_conditions()
    test_payload_generation()
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()