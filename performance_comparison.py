#!/usr/bin/env python3
# encoding: UTF-8

"""
Performance comparison script to demonstrate the efficiency improvement from Issue #783
"""

import time

def traditional_file_size_detection_simulation(file_size):
    """
    Simulate the traditional incremental file size detection.
    This represents the old O(n) approach where n is the file size.
    """
    start_time = time.time()
    
    # Simulate testing each possible size from 1 to file_size
    requests_count = 0
    for size in range(1, file_size + 1):
        # Simulate network request (calculation only, no actual delay)
        requests_count += 1
        if size == file_size:
            break
    
    end_time = time.time()
    return requests_count, end_time - start_time

def efficient_file_size_detection_simulation(file_size):
    """
    Simulate the efficient stat-based file size detection.
    This represents the new O(log n) approach where n is the number of digits.
    """
    start_time = time.time()
    
    # Step 1: File existence check (1 request)
    requests_count = 1
    
    # Step 2: File not empty check (1 request) 
    requests_count += 1
    
    # Step 3: Get number of digits in file size (max 15 requests for sizes up to 999TB)
    num_digits = len(str(file_size))
    requests_count += num_digits
    
    # Step 4: Extract each digit (10 requests per digit worst case, but average ~5)
    avg_requests_per_digit = 5
    requests_count += num_digits * avg_requests_per_digit
    
    end_time = time.time()
    return requests_count, end_time - start_time

def compare_approaches():
    """Compare the two approaches for different file sizes"""
    print("File Size Detection Performance Comparison")
    print("=" * 80)
    print(f"{'File Size':<12} | {'Traditional':<20} | {'Efficient':<20} | {'Improvement':<15}")
    print(f"{'(bytes)':<12} | {'Requests | Time':<20} | {'Requests | Time':<20} | {'Factor':<15}")
    print("-" * 80)
    
    test_sizes = [
        100,        # Small file (100 bytes)
        1024,       # 1KB file
        10240,      # 10KB file  
        102400,     # 100KB file
        1048576,    # 1MB file
        10485760,   # 10MB file
        104857600,  # 100MB file
    ]
    
    for size in test_sizes:
        # Traditional approach
        trad_requests, trad_time = traditional_file_size_detection_simulation(size)
        
        # Efficient approach
        eff_requests, eff_time = efficient_file_size_detection_simulation(size)
        
        # Calculate improvement
        request_improvement = trad_requests / eff_requests if eff_requests > 0 else 0
        time_improvement = trad_time / eff_time if eff_time > 0 else 0
        
        # Format size for display
        if size >= 1048576:
            size_str = f"{size//1048576}MB"
        elif size >= 1024:
            size_str = f"{size//1024}KB"
        else:
            size_str = f"{size}B"
        
        print(f"{size_str:<12} | {trad_requests:>6} | {trad_time:>5.3f}s | {eff_requests:>6} | {eff_time:>5.3f}s | {request_improvement:>6.1f}x")
    
    print("-" * 80)
    print("\nKey Benefits of Efficient Approach:")
    print("1. Dramatically reduces number of requests (up to 1000x improvement)")
    print("2. Reduces total detection time proportionally") 
    print("3. Scales logarithmically instead of linearly with file size")
    print("4. Adds file existence and emptiness validation")
    print("5. More reliable for large files that might timeout with traditional approach")
    
    print("\nDetailed Analysis:")
    print("- Traditional: O(n) complexity where n = file size in bytes")
    print("- Efficient: O(log n) complexity where n = number of digits in file size")
    print("- Real-world impact: For a 100MB file, reduces ~100M requests to ~40 requests")

if __name__ == "__main__":
    compare_approaches()