import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule, REDACTED


def _scrub(callback, action, body, public=False):
    names = ("task", "result") if public else ("_task", "_result")
    result = SimpleNamespace(**{names[0]: SimpleNamespace(action=action), names[1]: dict(body)})
    original = copy.deepcopy(body)
    callback._scrub(result)
    assert body == original
    return getattr(result, names[1])


def _payload(action, collision):
    values = ["x", "42", "~#q"]
    if action == "keeper_get_record":
        return {"login": [collision], "password": values}
    return [collision] + values


def _masked_payload(action):
    if action == "keeper_get_record":
        return {"login": [REDACTED], "password": [REDACTED] * 3}
    return [REDACTED] * 4


@pytest.mark.parametrize("action,key,collision", [
    ("keeper_get", "value", "value"),
    ("keeper_get", "value", "alue"),
    ("keeper_get_record", "record", "record"),
    ("keeper_get_record", "record", "cord"),
])
@pytest.mark.parametrize("public", [False, True])
def test_original_payload_key_is_masked_before_key_redaction(action, key, collision, public):
    callback = CallbackModule()
    body = {key: _payload(action, collision), "changed": False}
    clean = _scrub(callback, action, body, public)
    assert clean == {callback._redact_text(key): _masked_payload(action), "changed": False}


@pytest.mark.parametrize("action,key", list(CallbackModule.SECRET_RESULT_KEYS.items()))
def test_previously_learned_payload_key_cannot_expose_a_short_value(action, key):
    callback = CallbackModule()
    callback._learn("keeper_get", {"value": key})
    payload = {"password": ["~#q"]} if action == "keeper_get_record" else "~#q"
    masked = {"password": [REDACTED]} if action == "keeper_get_record" else REDACTED
    clean = _scrub(callback, action, {key: payload})
    assert clean == {REDACTED: masked}


@pytest.mark.parametrize("action,key,collision", [
    ("keeper_get", "value", "value"),
    ("keeper_get", "value", "results"),
    ("keeper_get_record", "record", "record"),
    ("keeper_get_record", "record", "results"),
])
@pytest.mark.parametrize("public", [False, True])
def test_item_and_aggregate_payloads_keep_masking_after_key_redaction(action, key, collision, public):
    callback = CallbackModule()
    items = [{key: _payload(action, value), "item": label}
             for value, label in ((collision, "first"), ("another-secret", "second"))]
    for item in items:
        clean = _scrub(callback, action, item, public)
        assert clean[callback._redact_text(key)] == _masked_payload(action)
    clean = _scrub(callback, action, {"results": items, "changed": False}, public)
    shown = clean[callback._redact_text("results")]
    assert [item[callback._redact_text(key)] for item in shown] == [_masked_payload(action)] * 2
    assert [item["item"] for item in shown] == ["first", "second"]


@pytest.mark.parametrize("action,key", [("keeper_get", "value"), ("keeper_get_record", "record")])
def test_payload_context_does_not_extend_into_unrelated_metadata(action, key):
    callback = CallbackModule()
    body = {key: _payload(action, key),
            "metadata": {key: ["safe", "~#q"], "results": [{key: "safe"}]}}
    clean = _scrub(callback, action, body)
    assert clean["metadata"] == {
        callback._redact_text(key): ["safe", "~#q"],
        "results": [{callback._redact_text(key): "safe"}],
    }


@pytest.mark.parametrize("payload_first", [False, True])
def test_colliding_display_keys_preserve_both_values(payload_first):
    callback = CallbackModule()
    entries = [("record", _payload("keeper_get_record", "record")), (REDACTED, "safe")]
    body = dict(entries if payload_first else reversed(entries))
    clean = _scrub(callback, "keeper_get_record", body)
    assert set(clean) == {REDACTED, REDACTED + "_2"}
    assert "safe" in clean.values()
    assert _masked_payload("keeper_get_record") in clean.values()


def test_short_values_stay_visible_only_in_later_unrelated_results():
    callback = CallbackModule()
    original = _payload("keeper_get", "long-secret")
    own = _scrub(callback, "keeper_get", {"value": original})
    assert own["value"] == _masked_payload("keeper_get")
    later = _scrub(callback, "debug", {"msg": original})
    assert later["msg"] == [REDACTED, "x", "42", "~#q"]


def test_native_action_results_mask_colliding_keys_without_changing_registered_values(tmp_path):
    from keeper_secrets_manager_core import mock
    from .ansible_test_framework import AnsibleTestFramework

    record = mock.Record(title="Key collision record", record_type="login")
    record.field("login", "record")
    record.field("password", ["value", "~#q"])
    response = mock.Response()
    response.add_record(record=record)
    playbook = tmp_path / "redact_keys.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost",
        "gather_facts": False,
        "tasks": [
            {"name": "Read the record", "keeper_get_record": {"uid": "{{ record_uid }}"},
             "register": "fetched_record"},
            {"name": "Read the values", "keeper_get": {
                "uid": "{{ record_uid }}", "field": "password", "allow_array": True},
             "register": "fetched_values"},
            {"name": "Verify registered values", "assert": {"quiet": True, "that": [
                "fetched_record.record.login == ['record']",
                "fetched_record.record.password == ['value', '~#q']",
                "fetched_values.value == ['value', '~#q']",
            ]}},
        ],
    }]), encoding="utf-8")
    framework = AnsibleTestFramework(
        playbook=str(playbook), stdout_callback="keeper_redact", mock_responses=[response],
        vars={"record_uid": record.uid, "keeper_config": mock.MockConfig.make_base64()})
    (tmp_path / "inventory").mkdir()
    shutil.copyfile(Path(framework.base_dir) / "inventory" / "all", tmp_path / "inventory" / "all")
    framework.base_dir = str(tmp_path)
    recap, out, err = framework.run()
    assert recap["failed"] == 0, out + err
    assert recap["ok"] == 3, out + err
    assert "Loading callback plugin keeper_redact" in out + err
    for name, following in (("Read the record", "Read the values"),
                            ("Read the values", "Verify registered values")):
        own = (out + err).split("TASK [" + name + "]", 1)[1].split("TASK [" + following + "]", 1)[0]
        assert "~#q" not in own
        assert json.dumps(REDACTED) in own
    assert "Failure using method" not in out + err
