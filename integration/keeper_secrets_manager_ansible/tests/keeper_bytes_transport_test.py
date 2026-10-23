import base64
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from .byte_transport_fixture import PAYLOADS, RECORD_UID


COMPONENT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_RUNNER = Path(__file__).with_name("byte_transport_fixture.py")


def _assert_results(variable, nested=False, lookup=False):
    expressions = ["{}.results | length == {}".format(variable, len(PAYLOADS))]
    for index, content in enumerate(PAYLOADS.values()):
        field = "ansible_facts.attachment" if lookup else "value"
        selector = "[0]" if nested or lookup else ""
        expressions.append("{}.results[{}].{}{} | b64encode == '{}'".format(
            variable, index, field, selector, base64.b64encode(content).decode("ascii"),
        ))
    return {"ansible.builtin.assert": {"that": expressions}, "no_log": True}


def _playbook(action, lookup, no_log):
    loop = list(PAYLOADS)
    tasks = [
        {
            "name": "Read a nonlooped attachment",
            action: {"uid": RECORD_UID, "file": "ascii.key"},
            "register": "direct", "no_log": no_log,
        },
        {
            "ansible.builtin.assert": {
                "that": ["direct.value | b64encode == '{}'".format(
                    base64.b64encode(PAYLOADS["ascii.key"]).decode("ascii"),
                )],
            },
            "no_log": True,
        },
        {
            "name": "Read string fields in a loop",
            action: {"uid": RECORD_UID, "field": "login"},
            "loop": ["one"], "register": "fields", "no_log": no_log,
        },
        {
            "ansible.builtin.assert": {"that": ["fields.results[0].value == 'fixture-user'"]},
            "no_log": True,
        },
    ]
    for variable, options in (
        ("scalar", {"uid": RECORD_UID, "file": "{{ item }}"}),
        ("nested", {"uid": RECORD_UID, "file": "{{ item }}", "allow_array": True}),
        ("notation", {"notation": RECORD_UID + "/file/{{ item }}"}),
    ):
        tasks.extend([
            {
                "name": "Read {} attachment results in a loop".format(variable),
                action: options, "loop": loop, "register": variable, "no_log": no_log,
            },
            _assert_results(variable, nested=variable == "nested"),
        ])
    tasks.extend([
        {
            "name": "Read attachments through a lookup",
            "ansible.builtin.set_fact": {
                "attachment": "{{ query('" + lookup + "', uid='" + RECORD_UID + "', file=item) }}",
            },
            "loop": loop, "register": "looked_up", "no_log": no_log,
        },
        _assert_results("looked_up", lookup=True),
    ])
    tasks.append({
        "name": "Verify downstream variable transport",
        "ansible.builtin.set_fact": {"forwarded": "{{ scalar.results[4].value }}"},
        "no_log": True,
    })
    tasks.append({
        "ansible.builtin.assert": {"that": [
            "forwarded | b64encode == '{}'".format(base64.b64encode(PAYLOADS["template.key"]).decode("ascii")),
        ]},
        "no_log": True,
    })
    return [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {
            "keeper_hostname": "fixture.invalid", "keeper_client_id": "fixture-client",
            "keeper_use_cache": False, "ansible_python_interpreter": sys.executable,
        },
        "tasks": tasks,
    }]


def _run_native(command, directory, env):
    with subprocess.Popen(
        command, cwd=directory, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", start_new_session=True,
    ) as proc:
        try:
            out, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate(timeout=10)
            pytest.fail("Native playbook exceeded its time limit.\n" + out + err)
    return proc.returncode, out + err


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="Requires POSIX process groups.")
@pytest.mark.parametrize("collection", [False, True], ids=["package", "collection"])
@pytest.mark.parametrize("callback", ["default", "keeper_redact"])
@pytest.mark.parametrize("no_log", [False, True], ids=["visible", "no_log"])
def test_native_attachment_results_preserve_bytes(tmp_path, collection, callback, no_log):
    package = Path(importlib.util.find_spec("keeper_secrets_manager_ansible").origin).parent
    plugins = package / "plugins"
    home, local = tmp_path / "home", tmp_path / "local"
    home.mkdir()
    local.mkdir()
    config, playbook, trace = tmp_path / "ansible.cfg", tmp_path / "playbook.yml", tmp_path / "trace.jsonl"
    config.write_text("[defaults]\nretry_files_enabled=False\nforks=1\n", encoding="utf-8")
    locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    env = {
        "HOME": str(home), "PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
        "LANG": locale, "LC_ALL": locale,
        "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(local),
        "ANSIBLE_NOCOLOR": "1", "PYTHONPATH": str(package.parent),
        "PYTHONDONTWRITEBYTECODE": "1", "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES",
    }
    action, lookup = "keeper_get", "keeper"
    if collection:
        root = tmp_path / "collections"
        destination = root / "ansible_collections/keepersecurity/keeper_secrets_manager"
        shutil.copytree(
            COMPONENT_DIR / "ansible_galaxy/keepersecurity/keeper_secrets_manager",
            destination,
        )
        shutil.copytree(plugins, destination / "plugins", ignore=shutil.ignore_patterns("__pycache__"))
        env["ANSIBLE_COLLECTIONS_PATH"] = str(root)
        env["ANSIBLE_COLLECTIONS_PATHS"] = str(root)
        action, lookup = "keepersecurity.keeper_secrets_manager.keeper_get", "keepersecurity.keeper_secrets_manager.keeper"
        if callback == "keeper_redact":
            callback = "keepersecurity.keeper_secrets_manager.keeper_redact"
    else:
        for key, directory in (
            ("ANSIBLE_ACTION_PLUGINS", "action"), ("ANSIBLE_LOOKUP_PLUGINS", "lookup"),
            ("ANSIBLE_LIBRARY", "modules"), ("ANSIBLE_CALLBACK_PLUGINS", "callback"),
        ):
            env[key] = str(plugins / directory)
    env["ANSIBLE_STDOUT_CALLBACK"] = callback
    playbook.write_text(yaml.safe_dump(_playbook(action, lookup, no_log)), encoding="utf-8")

    code, output = _run_native(
        [sys.executable, str(FIXTURE_RUNNER), "--playbook", str(playbook), "--trace", str(trace)], tmp_path, env,
    )

    assert code == 0, output
    for warning in ("Failure using", "Callback dispatch", "surrogates not allowed", "'super' object"):
        assert warning not in output, output
    if not no_log and callback.endswith("keeper_redact"):
        assert "****" in output, output
        for content in (PAYLOADS["ascii.key"], PAYLOADS["utf8.key"], PAYLOADS["template.key"]):
            text = content.decode("utf-8")
            assert text not in output and json.dumps(text)[1:-1] not in output, output
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    runtime = next(event for event in events if event["stage"] == "runtime")
    legacy = (runtime["python"][:2] in ([3, 9], [3, 10]) and
              runtime["ansible"].startswith(("2.15.", "2.16.")) and not runtime["native_bytes_method"])
    assert runtime["strip_changed"] is legacy, runtime
    observed = {event["sha256"] for event in events if event["stage"] == "value"}
    assert observed == {hashlib.sha256(content).hexdigest() for content in PAYLOADS.values()}
    assert set(PAYLOADS) == {event["name"] for event in events if event["stage"] == "download"}
