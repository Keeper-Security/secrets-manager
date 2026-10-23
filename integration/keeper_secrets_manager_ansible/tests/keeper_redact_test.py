import copy
from types import SimpleNamespace

import pytest
import yaml

from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, REDACTED
from .ansible_test_framework import AnsibleTestFramework


KEEPER_KEYS = (
    "keeper_config", "keeper_config_file", "keeper_client_id", "keeper_private_key", "keeper_app_key",
    "keeper_token", "keeper_record_cache_secret",
)


@pytest.mark.parametrize("value", [
    "secret", {"clientId": "secret"}, ["secret"], ("secret",), b"secret", bytearray(b"secret"),
    "", {}, [], 0, False, None,
])
def test_sensitive_settings_are_masked_without_changing_registered_values(value):
    values = dict.fromkeys(KEEPER_KEYS, value)
    body = dict(values, ansible_facts=dict(values), msg=[(dict(values),)],
                Keeper_nothing="secret", changed=False)
    original = copy.deepcopy(body)
    result = SimpleNamespace(result=body.copy(), task=SimpleNamespace(action="debug"))
    callback = CallbackModule()
    callback._learn("keeper_get", {"value": "keeper_private_key"})

    callback._scrub(result)

    masked = {REDACTED if key == "keeper_private_key" else key: REDACTED for key in KEEPER_KEYS}
    assert result.result == dict(masked, ansible_facts=masked, msg=[[masked]],
                                 Keeper_nothing="secret", changed=False)
    assert body == original


@pytest.mark.parametrize("stdout_callback", [None, "keeper_redact"], ids=["default", "redacted"])
def test_native_setting_output_is_masked_only_by_the_redacting_callback(tmp_path, stdout_callback):
    values = {key: "secret-for-" + key for key in KEEPER_KEYS}
    values["keeper_config"] = {"clientId": values["keeper_config"]}
    values["keeper_private_key"] = [values["keeper_private_key"]]
    values["Keeper_nothing"] = "public-value"
    tasks = [
        {"name": "Set sensitive facts", "set_fact": {key: "{{ sensitive." + key + " }}" for key in values},
         "register": "saved"},
        {"name": "Display sensitive facts", "debug": {"var": "saved.ansible_facts"}},
        {"name": "Display nested sensitive facts", "debug": {
            "msg": "{{ [saved.ansible_facts, {'nested': saved.ansible_facts}] }}"}},
        {"name": "Verify unchanged facts", "assert": {"quiet": True, "that": [
            "saved.ansible_facts == sensitive"] + [key + " == sensitive." + key for key in values]}},
    ]
    playbook = tmp_path / "settings.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": {"sensitive": values}, "tasks": tasks,
    }]), encoding="utf-8")
    (tmp_path / "inventory").mkdir()
    (tmp_path / "inventory" / "all").write_text("localhost ansible_connection=local\n", encoding="utf-8")
    framework = AnsibleTestFramework(playbook=str(playbook), stdout_callback=stdout_callback)
    framework.base_dir = str(tmp_path)

    status, out, err = framework.run()

    output = out + err
    assert status["ok"] == 4 and status["failed"] == 0, output
    assert "Loading callback plugin " + (stdout_callback or "default") in output
    assert "Callback dispatch" not in output and "Failure using" not in output
    for task in tasks[:3]:
        text = output.split("TASK [" + task["name"] + "]", 1)[1].split("TASK [", 1)[0]
        assert "public-value" in text
        for key in KEEPER_KEYS:
            assert key in text
            assert ("secret-for-" + key in text) == (stdout_callback is None)
        if stdout_callback:
            assert REDACTED in text
