"""Run a native playbook with synthetic encrypted attachments and no network."""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path


PAYLOADS = {
    "ascii.key": b"opaque ASCII attachment\n",
    "utf8.key": "opaque attachment: caf\u00e9\n".encode("utf-8"),
    "binary.key": b"\x00\x01\x80\xff\r\n",
    "empty.key": b"",
    "template.key": b"{{ 6 * 7 }}-literal-attachment\n",
    "all-bytes.key": bytes(range(256)),
}
RECORD_UID = "AAAAAAAAAAAAAAAAAAAAAA"


def append_event(path, event):
    event["pid"] = os.getpid()
    data = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--playbook", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    trace = Path(args.trace)

    import ansible.release
    from ansible.utils.unsafe_proxy import AnsibleUnsafeBytes

    original_strip = getattr(AnsibleUnsafeBytes, "_strip_unsafe", None)

    import requests
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.crypto import CryptoUtils
    from keeper_secrets_manager_core.dto.dtos import Record
    from keeper_secrets_manager_ansible import KeeperAnsible

    append_event(trace, {
        "stage": "runtime",
        "python": list(sys.version_info[:3]),
        "ansible": ansible.release.__version__,
        "native_bytes_method": hasattr(bytes, "__bytes__"),
        "strip_changed": getattr(AnsibleUnsafeBytes, "_strip_unsafe", None) is not original_strip,
    })

    record_key, file_key = b"R" * 32, b"F" * 32
    downloads, files = {}, []
    for index, (name, payload) in enumerate(PAYLOADS.items()):
        url = "https://fixture.invalid/" + name
        metadata = {"name": name, "title": name, "size": len(payload), "type": "application/octet-stream"}
        files.append({
            "fileUid": "fixture-file-{}".format(index),
            "fileKey": base64.b64encode(CryptoUtils.encrypt_aes(file_key, record_key)).decode("ascii"),
            "data": base64.b64encode(
                CryptoUtils.encrypt_aes(json.dumps(metadata).encode("utf-8"), file_key)
            ).decode("ascii"),
            "url": url,
        })
        downloads[url] = CryptoUtils.encrypt_aes(payload, file_key)
    record_data = {
        "title": "Synthetic attachment record", "type": "login",
        "fields": [{"type": "login", "value": ["fixture-user"]}], "custom": [],
    }
    record = Record({
        "recordUid": RECORD_UID,
        "data": base64.b64encode(
            CryptoUtils.encrypt_aes(json.dumps(record_data).encode("utf-8"), record_key)
        ).decode("ascii"),
        "files": files,
    }, record_key)

    def forbid_http(*unused_args, **unused_kwargs):
        raise AssertionError("Live HTTP is disabled in this fixture.")

    class FixtureClient(SecretsManager):
        def __init__(self):
            self.verify_ssl_certs = True
            self.proxy_url = None
            self.post_function = forbid_http

        @staticmethod
        def get_secrets(*unused_args, **unused_kwargs):
            return [record]

    def fixture_get(url, *unused_args, **unused_kwargs):
        if url not in downloads:
            raise AssertionError("Unexpected attachment URL.")
        response = requests.Response()
        response.status_code = 200
        response._content = downloads[url]
        append_event(trace, {"stage": "download", "name": url.rsplit("/", 1)[-1]})
        return response

    requests.get = fixture_get
    requests.post = forbid_http
    requests.sessions.Session.request = forbid_http
    KeeperAnsible.get_client = staticmethod(lambda **unused_kwargs: FixtureClient())
    original_get_value = KeeperAnsible.get_value

    def observed_get_value(self, *value_args, **value_kwargs):
        result = original_get_value(self, *value_args, **value_kwargs)
        values = result if isinstance(result, list) else [result]
        for value in values:
            if isinstance(value, bytes):
                append_event(trace, {
                    "stage": "value", "size": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                })
        return result

    KeeperAnsible.get_value = observed_get_value

    from ansible.cli.playbook import main as playbook_main

    sys.argv = ["ansible-playbook", "-v", "-i", "localhost,", args.playbook]
    playbook_main()


if __name__ == "__main__":
    main()
