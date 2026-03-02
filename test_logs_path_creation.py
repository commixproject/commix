#!/usr/bin/env python
# encoding: UTF-8

"""
Test suite for logs.py path_creation function
Tests the fix for issue #128 - Permission denied error handling
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock, mock_open, call

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.utils import logs
from src.utils import settings


class TestPathCreation(unittest.TestCase):
    """Test path_creation function with various scenarios"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp(prefix="commix_test_")
        # Suppress print output during tests
        settings.print_data_to_stdout = lambda x: None

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_path_creation_success(self):
        """Test successful directory creation"""
        test_path = os.path.join(self.test_dir, "new_dir")
        result = logs.path_creation(test_path)

        self.assertTrue(os.path.exists(test_path))
        self.assertEqual(result, test_path)

    def test_path_creation_already_exists(self):
        """Test when directory already exists"""
        test_path = os.path.join(self.test_dir, "existing_dir")
        os.mkdir(test_path)

        result = logs.path_creation(test_path)

        self.assertTrue(os.path.exists(test_path))
        self.assertEqual(result, test_path)

    @patch('os.mkdir')
    @patch('tempfile.mkdtemp')
    def test_path_creation_permission_denied(self, mock_mkdtemp, mock_mkdir):
        """Test fallback to temp directory on permission denied"""
        test_path = "/root/restricted/.output"
        temp_fallback = "/tmp/commix_test_fallback"

        # Mock permission denied error
        mock_mkdir.side_effect = OSError(13, "Permission denied")
        mock_mkdtemp.return_value = temp_fallback

        result = logs.path_creation(test_path)

        # Should return fallback path
        self.assertEqual(result, temp_fallback)
        mock_mkdtemp.assert_called_once_with(prefix=settings.APPLICATION)

    @patch('os.mkdir')
    @patch('tempfile.mkdtemp')
    def test_path_creation_permission_denied_temp_fails(self, mock_mkdtemp, mock_mkdir):
        """Test when both original and temp directory creation fail"""
        test_path = "/root/restricted/.output"

        # Mock both operations failing
        mock_mkdir.side_effect = OSError(13, "Permission denied")
        mock_mkdtemp.side_effect = OSError(13, "Permission denied")

        with self.assertRaises(SystemExit):
            logs.path_creation(test_path)

    @patch('os.mkdir')
    def test_path_creation_other_error(self, mock_mkdir):
        """Test non-permission OSError (e.g., disk full)"""
        test_path = os.path.join(self.test_dir, "test_dir")

        # Mock different error (not permission denied)
        mock_mkdir.side_effect = OSError(28, "No space left on device")

        with self.assertRaises(SystemExit):
            logs.path_creation(test_path)


class TestLogsFilenameCreation(unittest.TestCase):
    """Test logs_filename_creation with permission handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp(prefix="commix_test_")
        settings.print_data_to_stdout = lambda x: None

        # Mock menu.options
        self.mock_options = MagicMock()
        self.mock_options.output_dir = None
        self.mock_options.session_file = None
        self.mock_options.no_logging = False

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    @patch('src.utils.logs.menu')
    @patch('src.utils.logs.path_creation')
    def test_logs_filename_creation_with_fallback_path(self, mock_path_creation, mock_menu):
        """Test that logs_filename_creation uses fallback path correctly"""
        mock_menu.options = self.mock_options

        # Simulate fallback path being returned
        fallback_path = os.path.join(self.test_dir, "fallback")
        mock_path_creation.return_value = fallback_path

        test_url = "http://example.com/test"

        # Mock create_log_file to avoid file operations
        with patch('src.utils.logs.create_log_file') as mock_create:
            mock_create.return_value = "/test/logs.txt"
            result = logs.logs_filename_creation(test_url)

            # Verify path_creation was called
            mock_path_creation.assert_called_once()


class TestCreateLogFile(unittest.TestCase):
    """Test create_log_file with permission handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp(prefix="commix_test_")
        settings.print_data_to_stdout = lambda x: None
        settings.OUTPUT_FILE = "logs.txt"
        settings.DEFAULT_CODEC = "utf-8"
        settings.LOAD_SESSION = False
        settings.ANSI_COLOR_REMOVAL = r'\x1b\[[0-9;]*m'
        settings.INFO_BOLD_SIGN = "[+]"

        # Mock menu.options
        self.mock_options = MagicMock()
        self.mock_options.session_file = None
        self.mock_options.no_logging = False
        self.mock_options.output_dir = None

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    @patch('src.utils.logs.menu')
    @patch('src.utils.logs.path_creation')
    @patch('src.utils.logs.checks')
    def test_create_log_file_with_fallback_path(self, mock_checks, mock_path_creation, mock_menu):
        """Test that create_log_file handles fallback path correctly"""
        mock_menu.options = self.mock_options
        mock_checks.load_cmd_history = MagicMock()

        # Setup paths
        output_dir = os.path.join(self.test_dir, "output") + "/"
        fallback_path = os.path.join(self.test_dir, "fallback")

        # Create fallback directory
        os.makedirs(fallback_path)

        # Mock path_creation to return fallback
        mock_path_creation.return_value = fallback_path

        test_url = "http://example.com/test"

        result = logs.create_log_file(test_url, output_dir)

        # Verify the log file path contains fallback path
        self.assertIn(os.path.basename(fallback_path), result)


class TestIntegrationPermissionHandling(unittest.TestCase):
    """Integration tests for full workflow with permission errors"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_dir = tempfile.mkdtemp(prefix="commix_test_")
        settings.print_data_to_stdout = lambda x: None
        settings.OUTPUT_FILE = "logs.txt"
        settings.DEFAULT_CODEC = "utf-8"
        settings.LOAD_SESSION = False
        settings.ANSI_COLOR_REMOVAL = r'\x1b\[[0-9;]*m'
        settings.INFO_BOLD_SIGN = "[+]"

        # Mock menu.options
        self.mock_options = MagicMock()
        self.mock_options.output_dir = None
        self.mock_options.session_file = None
        self.mock_options.no_logging = False

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    @patch('src.utils.logs.menu')
    @patch('src.utils.logs.checks')
    def test_full_workflow_with_permission_error(self, mock_checks, mock_menu):
        """Test complete logs_filename_creation workflow with permission error"""
        mock_menu.options = self.mock_options
        mock_checks.load_cmd_history = MagicMock()

        # Setup fallback directory that actually exists
        fallback_dir = os.path.join(self.test_dir, "fallback")
        os.makedirs(fallback_dir)

        test_url = "http://example.com/test"

        # Use real path_creation but mock only the first mkdir call
        original_mkdir = os.mkdir
        call_count = [0]

        def mock_mkdir_selective(path):
            call_count[0] += 1
            # Fail only on the first call (for .output parent dir)
            if call_count[0] == 1:
                raise OSError(13, "Permission denied")
            else:
                # Succeed on subsequent calls (for fallback subdirs)
                return original_mkdir(path)

        with patch('os.mkdir', side_effect=mock_mkdir_selective):
            with patch('tempfile.mkdtemp', return_value=fallback_dir):
                # This should not raise SystemExit
                try:
                    result = logs.logs_filename_creation(test_url)
                    # Should return a path (either original or fallback)
                    self.assertIsNotNone(result)
                    self.assertIsInstance(result, str)
                    # Verify the result contains the fallback path
                    self.assertIn(os.path.basename(fallback_dir), result)
                except SystemExit:
                    self.fail("logs_filename_creation raised SystemExit on permission error")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
