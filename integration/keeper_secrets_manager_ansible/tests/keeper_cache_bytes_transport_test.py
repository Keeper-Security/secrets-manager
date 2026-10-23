import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

import pytest
import yaml

from .cache_bytes_transport_fixture import CACHE_SECRET, FIELD_VALUE, RECORD_UID


SOURCE = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("cache_bytes_transport_fixture.py")
CASE_TIMEOUT_SECONDS = 20


def _run_cache_playbook(directory, loop, callback, python_executable=None, source_root=None):
    directory.mkdir(parents=True, exist_ok=True)
    source = Path(source_root) if source_root is not None else SOURCE
    plugins = source / "keeper_secrets_manager_ansible" / "plugins"
    expected_path = directory / "expected-cache.bin"
    cache_expression = "cached_records.results[0].cache" if loop else "cached_records.cache"
    cache_task = {
        "name": "Cache a synthetic SDK record",
        "keeper_cache_records": {"uids": [RECORD_UID]},
        "register": "cached_records",
        "no_log": True,
    }
    if loop:
        cache_task["loop"] = ["one"]
    playbook = [{
        "hosts": "localhost",
        "connection": "local",
        "gather_facts": False,
        "vars": {
            "keeper_hostname": "fixture.invalid",
            "keeper_client_id": "synthetic-client",
            "keeper_use_cache": False,
            "keeper_record_cache_secret": CACHE_SECRET,
            "expected_cache_path": str(expected_path),
            "expected_field_value": FIELD_VALUE,
        },
        "tasks": [
            cache_task,
            {
                "name": "Verify exact registered cache bytes",
                "assert": {"that": [
                    "({} | b64encode) == "
                    "(lookup('ansible.builtin.file', expected_cache_path, rstrip=False) | b64encode)".format(
                        cache_expression
                    ),
                ]},
                "no_log": True,
            },
            {
                "name": "Read a field through the registered cache",
                "keeper_get": {
                    "uid": RECORD_UID,
                    "field": "password",
                    "cache": "{{ " + cache_expression + " }}",
                },
                "register": "fetched",
            },
            {
                "name": "Verify the registered field value",
                "assert": {"that": ["fetched.value == expected_field_value"]},
                "no_log": True,
            },
        ],
    }]
    playbook_path = directory / "playbook.yml"
    playbook_path.write_text(yaml.safe_dump(playbook, sort_keys=False), encoding="utf-8")
    config = directory / "ansible.cfg"
    config.write_text(
        "[defaults]\nstdout_callback={}\nforks=1\nretry_files_enabled=False\n".format(callback),
        encoding="utf-8",
    )
    trace = directory / "trace.jsonl"
    locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    environment = {
        "HOME": str(directory / "home"),
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": locale,
        "LC_ALL": locale,
        "PYTHONPATH": str(source),
        "PYTHONDONTWRITEBYTECODE": "1",
        "ANSIBLE_CONFIG": str(config),
        "ANSIBLE_ACTION_PLUGINS": str(plugins / "action"),
        "ANSIBLE_LOOKUP_PLUGINS": str(plugins / "lookup"),
        "ANSIBLE_LIBRARY": str(plugins / "modules"),
        "ANSIBLE_CALLBACK_PLUGINS": str(plugins / "callback"),
        "ANSIBLE_LOCAL_TEMP": str(directory / "ansible-local"),
        "ANSIBLE_REMOTE_TEMP": str(directory / "ansible-remote"),
        "ANSIBLE_STDOUT_CALLBACK": callback,
        "ANSIBLE_NOCOLOR": "1",
        "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES",
    }
    (directory / "home").mkdir(exist_ok=True)
    command = [
        python_executable or sys.executable, str(FIXTURE),
        "--playbook", str(playbook_path),
        "--trace", str(trace),
        "--expected-cache", str(expected_path),
    ]
    timed_out = False
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen(
            command, cwd=directory, env=environment, stdout=stdout, stderr=stderr, start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=CASE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                return_code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return_code = process.wait(timeout=3)
            # A tracker or worker can outlive its parent after SIGTERM.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
    return {
        "return_code": return_code,
        "timed_out": timed_out,
        "output": stdout_path.read_text() + stderr_path.read_text(),
        "events": events,
        "directory": str(directory),
    }


def _assert_cache_result(run, callback):
    output = run["output"]
    assert not run["timed_out"], "Native cache transport exceeded its timeout:\n" + output
    assert run["return_code"] == 0, output
    assert re.search(r"localhost\s+:\s+ok=4\s+changed=0\s+unreachable=0\s+failed=0\b", output), output

    events = run["events"]
    starts = [event for event in events if event["stage"] == "start"]
    encrypted = [event for event in events if event["stage"] == "encrypted_cache"]
    consumed = [event for event in events if event["stage"] == "cache_consumer"]
    restored = [event for event in events if event["stage"] == "decrypted_record"]
    reads = [event for event in events if event["stage"] == "synthetic_record_read"]
    assert len(starts) == len(encrypted) == len(consumed) == len(restored) == len(reads) == 1, events
    assert encrypted[0]["type"] == "bytes" and encrypted[0]["size"] > 0, events
    assert consumed[0]["exact"] and restored[0]["exact"], events
    assert consumed[0]["sha256"] == encrypted[0]["sha256"], events
    assert not any(event["stage"] == "forbidden_http" for event in events), events
    if starts[0]["bytes_has_dunder"]:
        assert starts[0]["unsafe_class_unchanged"] and starts[0]["unsafe_registry_unchanged"], events

    if callback == "keeper_redact":
        assert FIELD_VALUE not in output and "****" in output, output
    else:
        assert FIELD_VALUE in output, output
    for warning in ("Callback dispatch", "Failure using", "unusable", "'super' object has no attribute '__bytes__'"):
        assert warning not in output, output


@pytest.mark.skipif(os.name == "nt", reason="Native Ansible process groups require POSIX.")
@pytest.mark.parametrize("loop", [False, True], ids=["scalar-cache", "loop-cache"])
@pytest.mark.parametrize("callback", ["default", "keeper_redact"])
def test_encrypted_cache_bytes_reach_a_later_consumer_unchanged(tmp_path, loop, callback):
    _assert_cache_result(_run_cache_playbook(tmp_path, loop, callback), callback)
