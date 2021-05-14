import unittest
import os
import sys

from sm import storage
from sm.core import generate_transmission_key


class ConfigFileUnitTest(unittest.TestCase):

    def test_get_configs(self):
        fkvs = storage.FileKeyValueStorage()

        config = fkvs.read_storage()

        print(config)

    def test_transmission_key(self):
        for key_num in [1, 2, 3, 4, 5, 6]:
            key = generate_transmission_key(key_num)

            assert key['publicKeyId'] == key_num
            assert len(key['key']) == 32
            assert len(key['encryptedKey']) == 125
