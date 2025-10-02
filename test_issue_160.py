#!/usr/bin/env python3
# encoding: UTF-8

"""
Test script for Issue #160: Unhandled socket exception (Connection reset by peer)
Tests socket error handling in examine_request() and request_failed()
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock
from socket import error as SocketError

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from src.utils import settings
from src.thirdparty.six.moves import urllib as _urllib


class TestIssue160SocketErrors(unittest.TestCase):
    """Test socket error handling for Issue #160"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Import after path is set
        from src.core.requests import requests
        from src.core import main
        self.requests_module = requests
        self.main_module = main
        
        # Mock settings
        settings.VERBOSITY_LEVEL = 0
        settings.MAX_RETRIES = 3
        settings.TIMEOUT = 30
        settings.MULTI_TARGETS = False
        settings.CRAWLING = False
        settings.VALID_URL = True
        settings.TOTAL_OF_REQUESTS = 0
    
    def test_connection_reset_by_peer_errno_104(self):
        """Test handling of errno 104 (Connection reset by peer)"""
        # Create socket error with errno 104
        sock_error = SocketError(104, "Connection reset by peer")
        
        # Mock examine_request to raise socket error
        with patch('src.thirdparty.six.moves.urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = sock_error
            
            # Import after mocking
            from src.core import main
            
            # Create mock request and URL
            mock_request = Mock()
            test_url = "http://example.com/test"
            
            # Mock dependencies
            with patch('src.core.requests.headers.check_http_traffic'):
                with patch('src.utils.menu.options') as mock_options:
                    mock_options.proxy = None
                    mock_options.ignore_proxy = None
                    mock_options.retries = None
                    
                    # Mock print to capture error messages
                    with patch('src.utils.settings.print_data_to_stdout') as mock_print:
                        # Call examine_request - should handle the error gracefully
                        # It will call request_failed which may raise SystemExit
                        try:
                            result = main.examine_request(mock_request, test_url)
                            # If we get here, error was handled without SystemExit (e.g., CRAWLING mode)
                            self.assertIn(result, [None, False])
                        except SystemExit:
                            # SystemExit is acceptable - it means error was caught and handled
                            # The important thing is that we got a proper error message
                            self.assertTrue(mock_print.called, "Error message should be printed")
    
    def test_request_failed_handles_connection_reset(self):
        """Test that request_failed() properly formats connection reset errors"""
        from src.core.requests import requests
        
        # Create connection reset error
        sock_error = SocketError(104, "Connection reset by peer")
        
        # Mock settings for crawling mode (should not raise SystemExit)
        settings.CRAWLING = True
        settings.TOTAL_OF_REQUESTS = 5
        settings.VERBOSITY_LEVEL = 1
        
        # Mock print function
        with patch('src.utils.settings.print_data_to_stdout') as mock_print:
            result = requests.request_failed(sock_error)
            
            # Should return False in crawling mode
            self.assertFalse(result)
            
            # Verify error message was printed
            self.assertTrue(mock_print.called)
            
            # Check that the error message mentions connection reset
            call_args_str = str(mock_print.call_args_list)
            self.assertTrue(
                any(keyword in call_args_str.lower() for keyword in ['reset', 'connection', 'peer']),
                "Error message should mention connection reset"
            )
    
    def test_socket_error_with_multi_targets(self):
        """Test socket error handling when scanning multiple targets"""
        from src.core.requests import requests
        
        settings.MULTI_TARGETS = True
        settings.CRAWLING = False  # Even without crawling, MULTI_TARGETS affects behavior
        sock_error = SocketError(104, "Connection reset by peer")
        
        with patch('src.utils.settings.print_data_to_stdout') as mock_print:
            try:
                result = requests.request_failed(sock_error)
                # Should handle gracefully (may or may not raise depending on state)
            except SystemExit:
                # SystemExit is ok as long as error message was printed
                pass
            
            # Verify error was reported
            self.assertTrue(mock_print.called)
    
    def test_various_socket_errors(self):
        """Test handling of various socket error codes"""
        from src.core.requests import requests
        
        error_codes = [
            (104, "Connection reset by peer"),
            (111, "Connection refused"),
            (110, "Connection timed out"),
            (113, "No route to host"),
        ]
        
        # Use CRAWLING mode to avoid SystemExit
        settings.CRAWLING = True
        
        for errno, errmsg in error_codes:
            with self.subTest(errno=errno, errmsg=errmsg):
                sock_error = SocketError(errno, errmsg)
                
                with patch('src.utils.settings.print_data_to_stdout'):
                    result = requests.request_failed(sock_error)
                    
                    # Should be handled without exception in CRAWLING mode
                    self.assertFalse(result)
    
    def test_urllib_error_handling(self):
        """Test handling of urllib errors that wrap socket errors"""
        from src.core.requests import requests
        
        # URLError can wrap socket errors
        sock_error = SocketError(104, "Connection reset by peer")
        url_error = _urllib.error.URLError(sock_error)
        
        settings.CRAWLING = True  # Avoid SystemExit
        
        with patch('src.utils.settings.print_data_to_stdout'):
            result = requests.request_failed(url_error)
            self.assertFalse(result)
    
    def test_error_message_contains_helpful_info(self):
        """Test that error messages provide helpful information to users"""
        from src.core.requests import requests
        
        sock_error = SocketError(104, "Connection reset by peer")
        settings.TOTAL_OF_REQUESTS = 1
        settings.CRAWLING = True  # Avoid SystemExit for testing
        
        captured_messages = []
        
        def capture_print(msg):
            captured_messages.append(str(msg))
        
        with patch('src.utils.settings.print_data_to_stdout', side_effect=capture_print):
            requests.request_failed(sock_error)
        
        # Check that some error message was printed
        self.assertTrue(len(captured_messages) > 0)
        
        # Message should be about connection/reset/peer/network
        message_text = ' '.join(captured_messages).lower()
        self.assertTrue(
            any(keyword in message_text for keyword in 
                ['connection', 'reset', 'peer', 'network', 'target', 'url', 'host']),
            f"Error message should contain helpful keywords. Got: {message_text}"
        )


class TestIssue160Integration(unittest.TestCase):
    """Integration tests for Issue #160 fix"""
    
    def setUp(self):
        """Set up integration test fixtures"""
        settings.VERBOSITY_LEVEL = 0
        settings.MAX_RETRIES = 1
        settings.MULTI_TARGETS = False
        settings.CRAWLING = False
        settings.TOTAL_OF_REQUESTS = 0
    
    def test_full_request_flow_with_socket_error(self):
        """Test complete request flow when socket error occurs - should not raise unhandled exception"""
        from src.core import main
        
        # Mock the entire urlopen to raise socket error
        with patch('src.thirdparty.six.moves.urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = SocketError(104, "Connection reset by peer")
            
            mock_request = Mock()
            test_url = "http://example.com/test"
            
            # Mock all dependencies
            with patch('src.core.requests.headers.check_http_traffic'):
                with patch('src.utils.menu.options') as mock_options:
                    mock_options.proxy = None
                    mock_options.ignore_proxy = None
                    mock_options.retries = None
                    
                    with patch('src.utils.settings.print_data_to_stdout') as mock_print:
                        # The key test: should not raise an UNHANDLED exception
                        # SystemExit is OK (controlled exit), but socket.error should not propagate
                        try:
                            result = main.examine_request(mock_request, test_url)
                            # If no SystemExit, result should be None or False
                            self.assertIn(result, [None, False])
                        except SystemExit:
                            # SystemExit is acceptable - it's a controlled exit with error message
                            # The bug was UNHANDLED socket.error, not SystemExit
                            pass
                        except SocketError:
                            # This should NOT happen - means the bug still exists
                            self.fail("Socket error was not caught! Bug still exists.")
                        
                        # Verify error message was printed
                        self.assertTrue(mock_print.called, "Error message should be printed")
    
    def test_no_unhandled_exception_in_production_scenario(self):
        """Test that the original issue scenario doesn't crash with unhandled exception"""
        from src.core import main
        
        # Simulate the exact scenario from issue #160
        with patch('src.thirdparty.six.moves.urllib.request.urlopen') as mock_urlopen:
            # Simulate the exact error from the issue
            mock_urlopen.side_effect = SocketError(104, "Connection reset by peer")
            
            mock_request = Mock()
            test_url = "http://vulnerable.example.com/upload.php"
            
            with patch('src.core.requests.headers.check_http_traffic'):
                with patch('src.utils.menu.options') as mock_options:
                    mock_options.proxy = None
                    mock_options.ignore_proxy = None
                    mock_options.retries = None
                    mock_options.tor = False
                    
                    with patch('src.utils.settings.print_data_to_stdout'):
                        # The critical test: should not crash with unhandled socket.error
                        exception_raised = None
                        try:
                            main.examine_request(mock_request, test_url)
                        except SystemExit:
                            # Controlled exit is OK
                            exception_raised = SystemExit
                        except SocketError as e:
                            # Unhandled socket error - BUG!
                            exception_raised = SocketError
                            self.fail(f"Unhandled socket error: {e}")
                        except Exception as e:
                            # Other unhandled exception
                            exception_raised = type(e)
                            self.fail(f"Unexpected exception: {type(e).__name__}: {e}")
                        
                        # Should have either exited cleanly or raised SystemExit
                        self.assertIn(exception_raised, [None, SystemExit], 
                                     "Should handle error with either normal return or SystemExit")


def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestIssue160SocketErrors))
    suite.addTests(loader.loadTestsFromTestCase(TestIssue160Integration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == '__main__':
    print("=" * 70)
    print("Issue #160 - Socket Error Handling Tests")
    print("Testing: Connection reset by peer (errno 104) and related errors")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    # Print summary
    print()
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    print("=" * 70)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
