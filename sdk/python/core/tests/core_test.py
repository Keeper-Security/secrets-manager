import unittest

from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.keeper_globals import logger_name
import io
import logging
import re
import sys
from contextlib import redirect_stderr


class CoreTest(unittest.TestCase):

    def test_prepare_context(self):
        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")

        # Pass in the config
        secrets_manager = SecretsManager(config=config)

        # There should be no app key
        self.assertIsNone(secrets_manager.config.get(ConfigKeys.KEY_APP_KEY), "found the app key")

        context = secrets_manager.prepare_context()

        self.assertIsNotNone(context.transmissionKey.key, "did not find a transmission key")
        self.assertIsNotNone(context.clientId, "did nto find a client id")
        self.assertTrue(isinstance(context.clientId, bytes), "client id is not bytes")

    def test_log_level(self):

        """ Test log level.

        It almost impossible to test log level since the unit test initialize the logging. This means
        we have a root handler already. The SDK's basicConfig will not be used. We can set the log level.

        """

        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")

        # If the log_level is not set, disable the logger
        SecretsManager(config=config)
        self.assertEqual(True, logging.getLogger(logger_name).disabled, "logging in not disabled")

        with io.StringIO() as buf:
            with redirect_stderr(buf):
                sm = SecretsManager(config=config, log_level="DEBUG")
                self.assertEqual(False, logging.getLogger(logger_name).disabled, "logging in disabled")
                sm.logger.debug("THIS IS DEBUG")
                sm.logger.error("THIS IS ERROR")
                out = buf.getvalue()
                self.assertRegex(out, logger_name, 'did not find the logger name')
                self.assertRegex(out, r'THIS IS DEBUG', "did not find THIS IS DEBUG")
                self.assertRegex(out, r'THIS IS ERROR', "did not find THIS IS ERROR")

                sm = SecretsManager(config=config, log_level=logging.ERROR)
                self.assertEqual(False, logging.getLogger(logger_name).disabled, "logging in disabled")
                sm.logger.debug("NEW DEBUG")
                sm.logger.error("NEW ERROR")
                buf.flush()
                out = buf.getvalue()
                self.assertRegex(out, r'NEW ERROR', "did not find NEW ERROR")
                self.assertFalse(re.search(r'NEW DEBUG', out, re.MULTILINE), 'found NEW DEBUG')



        # Use whatever the logger has been set up as.
        #buf = io.StringIO()
        #logging.getLogger().handlers = [logging.StreamHandler(stream=buf)]