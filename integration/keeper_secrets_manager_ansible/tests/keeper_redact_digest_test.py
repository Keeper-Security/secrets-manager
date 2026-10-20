import hashlib
import json
from types import SimpleNamespace
from unittest.mock import call, patch

import pytest
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, DefaultCallbackBase, REDACTED


DIGEST_NAMES = ("sha1", "md5", "sha256")
SECRET_ACTIONS = [("keeper_get", "value"), ("keeper_get_record", "record"), ("keeper_password", "password")]


@pytest.mark.parametrize("unavailable", [("sha1",), ("md5",), ("sha256",), DIGEST_NAMES],
                         ids=["sha1", "md5", "sha256", "all"])
@pytest.mark.parametrize("action,key", SECRET_ACTIONS)
@pytest.mark.parametrize("event", ["v2_runner_on_ok", "v2_runner_on_failed", "v2_runner_item_on_failed"])
def test_unavailable_digest_preserves_secret_masking_and_callback_dispatch(unavailable, action, key, event):
    data = b"\xffExampleBinarySecretABC123"
    secret = AnsibleUnsafeText(data.decode("utf-8", "surrogateescape"))
    secrets = [secret, "AnotherSecretABC123"]
    secret_bytes = [data, secrets[1].encode()]
    registered = {key: secrets.copy()}
    result = SimpleNamespace(_result=registered.copy(), _task=SimpleNamespace(action=action))
    callback = CallbackModule()
    new_digest = hashlib.new
    digests = {name: [new_digest(name, value, usedforsecurity=False).hexdigest() for value in secret_bytes]
               for name in DIGEST_NAMES}

    def digest(name, value, **kwargs):
        if name in unavailable:
            raise ValueError("unsupported hash type")
        return new_digest(name, value, **kwargs)

    handler_args = (False,) if event == "v2_runner_on_failed" else ()
    with patch("keeper_secrets_manager_ansible.plugins.callback.keeper_redact.hashlib.new",
               side_effect=digest) as new, \
            patch.object(DefaultCallbackBase, event, return_value="rendered") as handler:
        assert getattr(callback, event)(result, *handler_args) == "rendered"

    handler.assert_called_once_with(result, *handler_args)
    assert new.call_args_list == [call(name, value, usedforsecurity=False)
                                  for value in secret_bytes for name in DIGEST_NAMES]
    assert result._result == {key: [REDACTED] * len(secrets)}
    assert registered == {key: secrets}
    forms = secrets + [json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1],
                       repr(secret)[1:-1], repr(data)[2:-1]]
    later = SimpleNamespace(_result={"forms": forms, "digests": digests.copy()},
                            _task=SimpleNamespace(action="debug"))

    callback._scrub(later)

    assert later._result == {
        "forms": [REDACTED] * len(forms),
        "digests": {name: values if name in unavailable else [REDACTED] * len(secrets)
                    for name, values in digests.items()},
    }


@pytest.mark.parametrize("action,key", SECRET_ACTIONS)
@pytest.mark.parametrize("binary_type", [bytes, bytearray, AnsibleUnsafeText])
@pytest.mark.parametrize("public_result", [False, True], ids=["legacy-result", "public-result"])
def test_fips_digest_is_learned_when_security_use_is_blocked(action, key, binary_type, public_result):
    data = b"\xffExampleBinarySecretABC123"
    secret = (binary_type(data.decode("utf-8", "surrogateescape")) if binary_type is AnsibleUnsafeText else
              binary_type(data))
    registered = {key: secret}
    fields = ({"result": registered.copy(), "task": SimpleNamespace(action=action)} if public_result else
              {"_result": registered.copy(), "_task": SimpleNamespace(action=action)})
    result = SimpleNamespace(**fields)
    callback = CallbackModule()
    new_digest = hashlib.new
    digests = [new_digest(name, data, usedforsecurity=False).hexdigest() for name in DIGEST_NAMES]

    def digest(name, value, **kwargs):
        if name == "md5" and kwargs.get("usedforsecurity", True):
            raise ValueError("MD5 is disabled for security use")
        return new_digest(name, value, **kwargs)

    with pytest.raises(ValueError, match="disabled for security use"):
        digest("md5", data)
    with patch("keeper_secrets_manager_ansible.plugins.callback.keeper_redact.hashlib.new",
               side_effect=digest) as new, \
            patch.object(DefaultCallbackBase, "v2_runner_on_ok", return_value="rendered") as handler:
        assert callback.v2_runner_on_ok(result) == "rendered"

    handler.assert_called_once_with(result)
    assert (result.result if public_result else result._result) == {key: REDACTED}
    assert registered == {key: secret}
    later = SimpleNamespace(_result={"digests": digests}, _task=SimpleNamespace(action="debug"))

    callback._scrub(later)

    assert later._result == {"digests": [REDACTED] * len(DIGEST_NAMES)}
    assert new.call_args_list == [call(name, data, usedforsecurity=False) for name in DIGEST_NAMES]


@pytest.mark.parametrize("surrogate", [0xD800, 0xDBFF, 0xDC00, 0xDC7F, 0xDFFF])
@pytest.mark.parametrize("action,key", SECRET_ACTIONS)
def test_unencodable_text_preserves_masking_dispatch_and_later_secret_learning(surrogate, action, key):
    secret = "ExampleSecret" + chr(surrogate) + "ABC123"
    encodable_secret = "AnotherSecretABC123"
    registered = {key: [secret, encodable_secret]}
    result = SimpleNamespace(_result=registered.copy(), _task=SimpleNamespace(action=action))
    callback = CallbackModule()
    new_digest = hashlib.new
    digests = [new_digest(name, encodable_secret.encode(), usedforsecurity=False).hexdigest()
               for name in DIGEST_NAMES]

    with patch("keeper_secrets_manager_ansible.plugins.callback.keeper_redact.hashlib.new",
               wraps=new_digest) as new, \
            patch.object(DefaultCallbackBase, "v2_runner_on_ok", return_value="rendered") as handler:
        assert callback.v2_runner_on_ok(result) == "rendered"

    handler.assert_called_once_with(result)
    assert new.call_args_list == [call(name, encodable_secret.encode(), usedforsecurity=False)
                                  for name in DIGEST_NAMES]
    assert result._result == {key: [REDACTED, REDACTED]}
    assert registered == {key: [secret, encodable_secret]}
    forms = [secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], repr(secret)[1:-1]]
    later = SimpleNamespace(_result={"forms": forms, "digests": digests},
                            _task=SimpleNamespace(action="debug"))

    callback._scrub(later)

    assert later._result == {"forms": [REDACTED] * len(forms), "digests": [REDACTED] * len(DIGEST_NAMES)}
