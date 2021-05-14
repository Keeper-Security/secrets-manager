import hashlib
import os
import unittest

from keepercommandersm.utils import encrypt_aes, decrypt_aes


class BATTokenTest(unittest.TestCase):

    def test_decryption_with_bat_token(self):

        secret_key = os.urandom(32)

        plain_text_bytes = b"ABC123"
        encr_text_bytes = encrypt_aes(plain_text_bytes, secret_key)

        h = hashlib.new('sha256')
        h.update(secret_key)
        hash = h.digest()

        decrypted_plain_text_bytes = decrypt_aes(encr_text_bytes, secret_key)

        self.assertEqual(decrypted_plain_text_bytes, plain_text_bytes)


if __name__ == '__main__':
    unittest.main()
