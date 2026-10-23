import base64
import copy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from requests import Response
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, REDACTED

from .ansible_test_framework import AnsibleTestFramework


ATTACHMENTS = [
    pytest.param(b'attachment"secret\\123', id="text"),
    pytest.param(b"-----BEGIN KEY-----\nprivate-key-material\n-----END KEY-----", id="pem"),
    pytest.param("cl\u00e9-confidentielle".encode(), id="utf8"),
    pytest.param(b"\xffbinary\x00\xfe\x80secret", id="binary"),
]
SHORT_VALUES = [pytest.param(b"~#q", id="short"), pytest.param("\U0001f512".encode(), id="one-character")]


@pytest.mark.parametrize("content", ATTACHMENTS + SHORT_VALUES)
@pytest.mark.parametrize("binary_type", [bytes, bytearray])
@pytest.mark.parametrize("nested", [False, True], ids=["scalar", "array"])
def test_attachment_masking_preserves_registered_value(content, binary_type, nested):
    value = binary_type(content)
    registered = {"value": [{"file": value}] if nested else value}
    original = copy.deepcopy(registered)
    result = SimpleNamespace(result=registered.copy(), task=SimpleNamespace(action="keeper_get"))

    CallbackModule()._scrub(result)

    assert result.result["value"] == ([{"file": REDACTED}] if nested else REDACTED)
    assert registered == original


@pytest.mark.parametrize("content", ATTACHMENTS + SHORT_VALUES)
@pytest.mark.parametrize("legacy_text", [False, True], ids=["bytes", "decoded"])
def test_later_attachment_values_and_raw_byte_digests_are_redacted(content, legacy_text):
    text = content.decode("utf-8", "surrogateescape")
    callback = CallbackModule()
    callback._scrub(SimpleNamespace(
        result={"value": text if legacy_text else content}, task=SimpleNamespace(action="keeper_get")
    ))
    digests = [hashlib.new(name, content, usedforsecurity=False).hexdigest() for name in ("sha1", "md5", "sha256")]
    registered = {
        "raw": content, "mutable": bytearray(content), "text": text,
        "json": json.dumps(text)[1:-1], "repr": repr(text)[1:-1],
        "bytes_repr": repr(content)[2:-1], "digests": digests,
    }
    original = copy.deepcopy(registered)
    result = SimpleNamespace(result=registered.copy(), task=SimpleNamespace(action="debug"))

    callback._scrub(result)

    if len(text) >= callback.MIN_MATCH_LENGTH:
        assert result.result == dict.fromkeys(registered, REDACTED) | {"digests": [REDACTED] * 3}
    else:
        assert result.result == dict(registered, raw=text, mutable=text)
        assert not callback._learned
    assert registered == original


@pytest.mark.parametrize("content", [ATTACHMENTS[0], ATTACHMENTS[-1]])
@pytest.mark.parametrize("selector", ["file", "notation"])
def test_sdk_attachment_action_and_callback_preserve_and_hide_bytes(tmp_path, content, selector):
    record = mock.Record(title="Attachment record", record_type="login")
    attachment = record.add_file(name="binary.pem", title="binary.pem", content=content)
    response = mock.Response()
    response.add_record(record=record)
    digests = [hashlib.new(name, content, usedforsecurity=False).hexdigest() for name in ("sha1", "md5", "sha256")]
    args = ({"uid": "{{ record_uid }}", "file": "binary.pem"} if selector == "file" else
            {"notation": "{{ record_uid }}/file/binary.pem"})
    playbook = tmp_path / "attachments.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False,
        "vars": {"attachment_digests": digests},
        "tasks": [
            {"name": "Read attachment", "keeper_get": args, "register": "fetched"},
            {"name": "Verify registered bytes", "assert": {"that": [
                'fetched.value | b64encode == "{}"'.format(base64.b64encode(content).decode())
            ]}, "no_log": True},
            {"name": "Display attachment", "debug": {"var": "fetched.value"}},
            # Ansible's hash filter treats MD5 as a security operation, which a FIPS controller may reject.
            {"name": "Display attachment digests", "debug": {"msg": "{{ attachment_digests | to_json }}"}},
        ],
    }]), encoding="utf-8")

    def download(*args, **kwargs):
        downloaded = Response()
        downloaded.status_code = 200
        downloaded._content = attachment.downloadable_content()
        return downloaded

    with patch("requests.get", side_effect=download):
        status, out, err = AnsibleTestFramework(
            playbook=str(playbook), stdout_callback="keeper_redact",
            vars={"record_uid": record.uid}, mock_responses=[response]
        ).run()
    output = out + err
    assert status["ok"] == 4 and status["failed"] == 0, output
    assert "Loading callback plugin keeper_redact" in output
    assert "censored" in output and REDACTED in output
    own = output.split("TASK [Read attachment]", 1)[1].split("TASK [Verify registered bytes]", 1)[0]
    assert "ok: [localhost]" in own and '"value": "****"' in own, output
    for warning in ("Callback dispatch", "Failure using", "surrogates not allowed"):
        assert warning not in output
    text = content.decode("utf-8", "surrogateescape")
    for form in (text, json.dumps(text)[1:-1], repr(text)[1:-1], repr(content)[2:-1]):
        assert form not in output
    for digest in digests:
        assert digest not in output
