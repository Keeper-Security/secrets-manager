"""Run native Ansible with a synthetic encrypted record cache."""

import argparse
import base64
import copyreg
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys


RECORD_UID = "BBBBBBBBBBBBBBBBBBBBBB"
FIELD_VALUE = "synthetic-cache-transport-password"
CACHE_SECRET = "synthetic-cache-transport-secret"


def _event(path, stage, **details):
    data = json.dumps(dict(details, stage=stage, pid=os.getpid()), sort_keys=True).encode("utf-8") + b"\n"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--playbook", required=True)
    parser.add_argument("--trace", required=True)
    parser.add_argument("--expected-cache", required=True)
    args = parser.parse_args()
    trace = Path(args.trace)
    expected_path = Path(args.expected_cache)

    from ansible.utils.unsafe_proxy import AnsibleUnsafeBytes

    missing = object()
    unsafe_class_before = dict(vars(AnsibleUnsafeBytes))
    reducer_before = copyreg.dispatch_table.get(AnsibleUnsafeBytes, missing)

    from keeper_secrets_manager_ansible import KeeperAnsible
    from keeper_secrets_manager_core.crypto import CryptoUtils
    from keeper_secrets_manager_core.dto.dtos import Record
    import requests

    unsafe_class_after = dict(vars(AnsibleUnsafeBytes))
    _event(
        trace, "start",
        python=sys.version,
        ansible_core=importlib.metadata.version("ansible-core"),
        sdk=importlib.metadata.version("keeper-secrets-manager-core"),
        bytes_has_dunder=hasattr(bytes, "__bytes__"),
        unsafe_class_unchanged=(
            unsafe_class_before.keys() == unsafe_class_after.keys()
            and all(unsafe_class_after[name] is value for name, value in unsafe_class_before.items())
        ),
        unsafe_registry_unchanged=copyreg.dispatch_table.get(AnsibleUnsafeBytes, missing) is reducer_before,
    )

    record_key = b"c" * 32
    record_data = {
        "title": "Synthetic cache transport record",
        "type": "login",
        "fields": [{"type": "password", "value": [FIELD_VALUE]}],
        "custom": [],
    }
    record = Record({
        "recordUid": RECORD_UID,
        "data": base64.b64encode(
            CryptoUtils.encrypt_aes(json.dumps(record_data).encode("utf-8"), record_key)
        ).decode("ascii"),
        "revision": 1,
        "isEditable": True,
    }, record_key)

    def forbidden_request(*unused_args, **unused_kwargs):
        _event(trace, "forbidden_http")
        raise AssertionError("Live HTTP requests are disabled in this fixture.")

    class FixtureClient:
        verify_ssl_certs = True

        def __init__(self):
            self.post_function = forbidden_request

        @staticmethod
        def get_secrets(*unused_args, **unused_kwargs):
            _event(trace, "synthetic_record_read")
            return [record]

    requests.sessions.Session.request = forbidden_request
    requests.get = forbidden_request
    requests.post = forbidden_request
    KeeperAnsible.get_client = staticmethod(lambda **unused_kwargs: FixtureClient())
    original_encrypt = KeeperAnsible.encrypt
    original_decrypt = KeeperAnsible.decrypt

    def observed_encrypt(self, records):
        ciphertext = original_encrypt(self, records)
        fd = os.open(str(expected_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as expected:
            expected.write(ciphertext)
        _event(
            trace, "encrypted_cache",
            type=type(ciphertext).__name__,
            size=len(ciphertext),
            sha256=hashlib.sha256(ciphertext).hexdigest(),
        )
        return ciphertext

    def observed_decrypt(self, ciphertext):
        raw = ciphertext.encode("ascii") if isinstance(ciphertext, str) else memoryview(ciphertext).tobytes()
        _event(
            trace, "cache_consumer",
            exact=raw == expected_path.read_bytes(),
            size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )
        restored = original_decrypt(self, ciphertext)
        _event(
            trace, "decrypted_record",
            exact=len(restored) == 1 and restored[0].uid == RECORD_UID
            and restored[0].field("password", single=True) == FIELD_VALUE,
        )
        return restored

    KeeperAnsible.encrypt = observed_encrypt
    KeeperAnsible.decrypt = observed_decrypt

    from ansible.cli.playbook import main as playbook_main

    sys.argv = ["ansible-playbook", "-v", "-i", "localhost,", args.playbook]
    playbook_main()


if __name__ == "__main__":
    main()
