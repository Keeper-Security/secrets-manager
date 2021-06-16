import unittest

from keepercommandersm.storage import InMemoryKeyValueStorage
from keepercommandersm.configkeys import ConfigKeys
from keepercommandersm import Commander


class CoreTest(unittest.TestCase):

    def test_prepare_context(self):
        config = InMemoryKeyValueStorage()
        config.set(ConfigKeys.KEY_CLIENT_KEY, "MY CLIENT KEY")
        config.set(ConfigKeys.KEY_APP_KEY, "MY APP KEY")

        # Pass in the config
        c = Commander(config=config)

        # There should be no app key
        self.assertIsNone(c.config.get(ConfigKeys.KEY_APP_KEY), "found the app key")

        context = c.prepare_context()

        self.assertIsNotNone(context.transmissionKey.key, "did not find a transmission key")
        self.assertIsNotNone(context.clientId, "did nto find a client id")
        self.assertTrue(isinstance(context.clientId, bytes), "client id is not bytes")
