import logging
import unittest
from keeper_secrets_manager_core.keeper_globals import logger_name
from click.testing import CliRunner as ClickCliRunner


def _cleanup_logger_handlers():
    """
    Remove and close all handlers from the KSM logger.
    Replace with NullHandler to prevent any output during tests.
    """
    logger = logging.getLogger(logger_name)
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        try:
            handler.close()
        except:
            pass
    # Add NullHandler to prevent any logging output during tests
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    # Disable logger to prevent any output
    logger.disabled = True


class CliRunner(ClickCliRunner):
    """
    Wrapper around Click's CliRunner that cleans up logger handlers before and after each invoke().

    Problem: Click's CliRunner redirects stderr/stdout during each invoke() call.
    When SecretsManager creates logging handlers, they capture the redirected stream.
    After invoke() completes, Click closes that stream, leaving stale handlers that fail
    on subsequent invoke() calls with "ValueError: I/O operation on closed file."

    Solution: This wrapper automatically cleans up handlers before and after each invoke() call,
    and replaces them with NullHandler to prevent logging output pollution.
    """

    def invoke(self, *args, **kwargs):
        """Invoke CLI command with logger cleanup before and after."""
        # Clean up before to remove stale handlers from previous invoke() calls
        _cleanup_logger_handlers()
        try:
            return super().invoke(*args, **kwargs)
        finally:
            # Clean up after to prevent handlers from polluting subsequent tests
            _cleanup_logger_handlers()


class KSMTestCase(unittest.TestCase):
    """
    Base test case for KSM CLI tests that handles logger cleanup.

    This ensures handlers are cleaned up before and after each test, even if tests
    don't use the CliRunner wrapper.
    """

    def setUp(self):
        """Clean up any existing handlers before the test starts."""
        _cleanup_logger_handlers()
        super().setUp()

    def tearDown(self):
        """Clean up handlers after the test completes."""
        super().tearDown()
        _cleanup_logger_handlers()
