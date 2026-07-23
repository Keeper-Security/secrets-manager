# -*- coding: utf-8 -*-
"""Unit tests for JSON-based record cache encrypt/decrypt (VM-1452 / CWE-502)."""

import base64
import io
import os
import pickle
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# ansible-core imports fcntl (unavailable on Windows). Stub ansible for unit tests
# that only exercise encrypt/decrypt crypto, not the full plugin runtime.
try:
    import fcntl  # noqa: F401
except ImportError:
    _ansible_stub = MagicMock()
    sys.modules.setdefault("ansible", _ansible_stub)
    sys.modules.setdefault("ansible.utils", _ansible_stub)
    sys.modules.setdefault("ansible.utils.display", _ansible_stub)
    sys.modules.setdefault("ansible.errors", _ansible_stub)
    sys.modules.setdefault("ansible.module_utils", _ansible_stub)
    sys.modules.setdefault("ansible.module_utils.basic", _ansible_stub)
    sys.modules.setdefault("ansible.module_utils.common", _ansible_stub)
    sys.modules.setdefault("ansible.module_utils.common.text", _ansible_stub)
    sys.modules.setdefault("ansible.module_utils.common.text.converters", _ansible_stub)
    _ansible_stub.errors.AnsibleError = Exception
    _ansible_stub.module_utils.basic.missing_required_lib = lambda name: name
    _ansible_stub.module_utils.common.text.converters.jsonify = lambda x: str(x)
    _ansible_stub.utils.display.Display = MagicMock

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from keeper_secrets_manager_core.dto.dtos import Record

from keeper_secrets_manager_ansible import KeeperAnsible


def _make_record(uid="uid123", title="Test Record", password="secret-pass"):
    """Build a minimal Record suitable for cache serialize/deserialize."""
    record = Record.__new__(Record)
    record.uid = uid
    record.title = title
    record.type = "login"
    record.dict = {
        "title": title,
        "type": "login",
        "fields": [
            {"type": "login", "value": ["user1"]},
            {"type": "password", "value": [password]},
        ],
        "custom": [],
    }
    record.raw_json = None
    record.record_key_bytes = os.urandom(32)
    record.folder_uid = ""
    record.inner_folder_uid = ""
    record.revision = 1
    record.is_editable = True
    record.password = password
    record.links = []
    record.files = []
    return record


def _stub_keeper(cache_secret="unit-test-cache-secret"):
    """Return a KeeperAnsible instance with __init__ bypassed."""
    with patch.object(KeeperAnsible, "__init__", lambda self, *a, **k: None):
        keeper = KeeperAnsible.__new__(KeeperAnsible)
    keeper.task_vars = {"keeper_record_cache_secret": cache_secret}
    keeper.client = MagicMock()
    keeper.action_module = None
    return keeper


class KeeperCacheEncryptTest(unittest.TestCase):

    def test_encrypt_decrypt_round_trip(self):
        keeper = _stub_keeper()
        original = _make_record()

        ciphertext = keeper.encrypt([original])
        restored = keeper.decrypt(ciphertext)

        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].uid, original.uid)
        self.assertEqual(restored[0].title, original.title)
        self.assertEqual(restored[0].type, original.type)
        self.assertEqual(restored[0].dict, original.dict)
        self.assertEqual(restored[0].record_key_bytes, original.record_key_bytes)
        self.assertEqual(restored[0].field("password"), ["secret-pass"])
        self.assertEqual(restored[0].field("login"), ["user1"])

    def test_decrypt_rejects_pickle_payload(self):
        """Encrypted pickle must not execute; decrypt must fail safely (VM-1452)."""
        cache_secret = "attacker-controlled-secret-12345"
        proof_path = None

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            proof_path = tmp.name
        try:
            if os.path.exists(proof_path):
                os.remove(proof_path)

            class Exploit:
                def __reduce__(self):
                    return (open, (proof_path, "w"))

            hostname = socket.gethostname()
            salt = hostname.zfill(32)[0:32]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode(),
                iterations=390000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(cache_secret.encode()))
            buf = io.BytesIO()
            pickle.dump(Exploit(), buf)
            malicious = Fernet(key).encrypt(buf.getvalue())

            keeper = _stub_keeper(cache_secret=cache_secret)
            with self.assertRaises(ValueError):
                keeper.decrypt(malicious)

            self.assertFalse(
                os.path.exists(proof_path),
                "pickle payload must not execute during decrypt",
            )
        finally:
            if proof_path and os.path.exists(proof_path):
                os.remove(proof_path)

    def test_decrypt_rejects_invalid_json_shape(self):
        keeper = _stub_keeper()
        secret_key = keeper.get_encryption_key()
        bad = Fernet(secret_key).encrypt(b'{"not": "a list"}')
        with self.assertRaises(ValueError) as ctx:
            keeper.decrypt(bad)
        self.assertIn("keeper_cache_records", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
