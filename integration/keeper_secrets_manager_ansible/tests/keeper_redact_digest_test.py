import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, DefaultCallbackBase, REDACTED


@pytest.mark.parametrize("unavailable", ["sha1", "md5", "sha256"])
def test_unavailable_digest_preserves_secret_masking_and_callback_dispatch(unavailable):
    data = b"\xffExampleBinarySecretABC123"
    secret = AnsibleUnsafeText(data.decode("utf-8", "surrogateescape"))
    secrets = [secret, "AnotherSecretABC123"]
    registered = {"value": secrets.copy()}
    result = SimpleNamespace(_result=registered.copy(), _task=SimpleNamespace(action="keeper_get"))
    callback = CallbackModule()
    new_digest = hashlib.new
    digests = {name: new_digest(name, data).hexdigest() for name in ("sha1", "md5", "sha256")}

    def digest(name, value):
        if name == unavailable:
            raise ValueError("unsupported hash type")
        return new_digest(name, value)

    with patch("keeper_secrets_manager_ansible.plugins.callback.keeper_redact.hashlib.new", side_effect=digest), \
            patch.object(DefaultCallbackBase, "v2_runner_on_ok", return_value="rendered") as handler:
        assert callback.v2_runner_on_ok(result) == "rendered"

    handler.assert_called_once_with(result)
    assert result._result == {"value": [REDACTED] * len(secrets)}
    assert registered == {"value": secrets}
    forms = secrets + [json.dumps(secret)[1:-1], repr(secret)[1:-1], repr(data)[2:-1]]
    later = SimpleNamespace(_result={"forms": forms, "digests": digests.copy()},
                            _task=SimpleNamespace(action="debug"))

    callback._scrub(later)

    assert later._result == {
        "forms": [REDACTED] * len(forms),
        "digests": {name: value if name == unavailable else REDACTED for name, value in digests.items()},
    }
