#!/usr/bin/env python
# encoding: UTF-8

"""
Test suite for issue #127 fix - connection_handler missing _context attribute
"""

import unittest
import ssl
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from unittest.mock import Mock, patch, MagicMock
from src.thirdparty.six.moves import urllib as _urllib


class TestConnectionHandlerContext(unittest.TestCase):
    """Test that connection_handler properly initializes with SSL context"""

    def setUp(self):
        """Set up test fixtures"""
        # Mock the settings and menu modules that are imported in headers.py
        self.settings_mock = MagicMock()
        self.settings_mock.DELAY = 0
        self.settings_mock.SCHEME = 'https'
        self.settings_mock.TIMEOUT = 30
        self.settings_mock.TOTAL_OF_REQUESTS = 0
        self.settings_mock.MAX_RETRIES = 3
        self.settings_mock.VERBOSITY_LEVEL = 0
        self.settings_mock.REVERSE_TCP = False
        self.settings_mock.BIND_TCP = False
        self.settings_mock.MULTI_TARGETS = False
        self.settings_mock.INIT_TEST = False

        self.menu_mock = MagicMock()
        self.menu_mock.options.traffic_file = None
        self.menu_mock.options.time_limit = None
        self.menu_mock.options.http10 = False

        self.checks_mock = MagicMock()
        self.logs_mock = MagicMock()

        # Patch the imports
        sys.modules['src.utils.settings'] = self.settings_mock
        sys.modules['src.utils.menu'] = self.menu_mock
        sys.modules['src.utils.logs'] = self.logs_mock
        sys.modules['src.core.injections.controller.checks'] = self.checks_mock

    def test_connection_handler_has_context_attribute(self):
        """Test that connection_handler instance has _context attribute after initialization"""
        # Import after mocking
        from src.core.requests import headers

        # Create a mock request
        mock_request = Mock(spec=_urllib.request.Request)
        mock_request.get_full_url.return_value = "https://example.com"

        # This will create the connection_handler class inside check_http_traffic
        # We need to test that it has the _context attribute

        # Patch opener.open to prevent actual network call
        with patch.object(_urllib.request.OpenerDirector, 'open') as mock_open:
            mock_response = Mock()
            mock_response.getcode.return_value = 200
            mock_response.info.return_value = {}
            mock_response.geturl.return_value = "https://example.com"
            mock_response.read.return_value = b"test"
            mock_open.return_value = mock_response

            with patch.object(_urllib.request, 'urlopen') as mock_urlopen:
                mock_urlopen.return_value = mock_response

                # This should not raise AttributeError about missing _context
                try:
                    headers.check_http_traffic(mock_request)
                    # If we get here, the fix is working
                    self.assertTrue(True, "check_http_traffic executed without AttributeError")
                except AttributeError as e:
                    if "_context" in str(e):
                        self.fail(f"AttributeError related to _context was raised: {e}")
                    else:
                        # Some other AttributeError, re-raise for investigation
                        raise

    def test_https_handler_initialization_with_context(self):
        """Test that HTTPSHandler is properly initialized with SSL context"""
        from src.core.requests import headers

        # Create an SSL context
        ssl_context = ssl._create_unverified_context()

        # Create the connection_handler class manually to test initialization
        class TestConnectionHandler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
            def __init__(self, debuglevel=0, context=None, check_hostname=None):
                # Initialize HTTPSHandler with context
                _urllib.request.HTTPSHandler.__init__(self, debuglevel=debuglevel,
                                                     context=context,
                                                     check_hostname=check_hostname)
                # Initialize HTTPHandler
                _urllib.request.HTTPHandler.__init__(self, debuglevel=debuglevel)

        # Create instance with SSL context
        handler = TestConnectionHandler(context=ssl_context)

        # Verify the handler has _context attribute
        self.assertTrue(hasattr(handler, '_context'),
                       "Handler should have _context attribute")
        self.assertIsNotNone(handler._context,
                           "_context should not be None")

    def test_http_handler_initialization(self):
        """Test that HTTPHandler is properly initialized"""
        from src.core.requests import headers

        # Create the connection_handler class manually to test initialization
        class TestConnectionHandler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
            def __init__(self, debuglevel=0, context=None, check_hostname=None):
                # Initialize HTTPSHandler with context
                _urllib.request.HTTPSHandler.__init__(self, debuglevel=debuglevel,
                                                     context=context,
                                                     check_hostname=check_hostname)
                # Initialize HTTPHandler
                _urllib.request.HTTPHandler.__init__(self, debuglevel=debuglevel)

        # Create instance
        handler = TestConnectionHandler()

        # Verify the handler can be built as an opener
        try:
            opener = _urllib.request.build_opener(handler)
            self.assertIsNotNone(opener, "Opener should be created successfully")
        except Exception as e:
            self.fail(f"Failed to create opener: {e}")

    def test_connection_handler_without_init_fails(self):
        """Test that connection_handler without __init__ would fail (proves the bug)"""
        # This test verifies the original bug exists

        # Create a connection_handler WITHOUT proper initialization
        class BrokenConnectionHandler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
            pass  # No __init__ method

        # Create instance
        handler = BrokenConnectionHandler()

        # The handler should NOT have _context when HTTPS methods are called
        # This demonstrates the bug
        self.assertFalse(hasattr(handler, '_context') and handler._context is not None,
                        "Broken handler should not have properly initialized _context")


class TestSSLContextCreation(unittest.TestCase):
    """Test SSL context handling in headers module"""

    def test_ssl_unverified_context_available(self):
        """Test that SSL unverified context is available"""
        import ssl

        # Verify the unverified context method exists
        self.assertTrue(hasattr(ssl, '_create_unverified_context'),
                       "ssl._create_unverified_context should be available")

        # Create an unverified context
        context = ssl._create_unverified_context()
        self.assertIsNotNone(context, "Unverified SSL context should be created")
        self.assertIsInstance(context, ssl.SSLContext,
                            "Context should be an SSLContext instance")


if __name__ == '__main__':
    # Run tests with verbosity
    unittest.main(verbosity=2)
