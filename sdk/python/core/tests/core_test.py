import unittest

from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import SecretsManager


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
