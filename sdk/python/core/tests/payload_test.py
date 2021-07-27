import unittest
from keeper_secrets_manager_core import SecretsManager


class PayloadTest(unittest.TestCase):

    def test_transmission_key(self):
        for key_num in [1, 2, 3, 4, 5, 6]:
            transmission_key = SecretsManager.generate_transmission_key(key_num)

            self.assertEqual(key_num, transmission_key.publicKeyId, "public key id does not match the key num")
            self.assertEqual(32, len(transmission_key.key), "The transmission key is not 32 bytes long")
            self.assertEqual(125, len(transmission_key.encryptedKey), "The transmission encryptedKey is not 125 bytes"
                                                                      "long")
