import builtins
import copy
import importlib
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

from keeper_secrets_manager_ansible import _ansible_compat as compat


MISSING_BYTES = "'super' object has no attribute '__bytes__'"
PAYLOADS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"attachment\r\n", id="ascii"),
    pytest.param("caf\u00e9\U0001f512".encode("utf-8"), id="utf8"),
    pytest.param(b"\x00\xff\x80\xfe\r\n", id="binary"),
    pytest.param(bytes(range(256)), id="all-byte-values"),
    pytest.param(b"{{ secret }}{% if value %}literal{% endif %}", id="template-like"),
]


def missing_bytes(value):
    raise AttributeError(MISSING_BYTES)


class FixtureUnsafeBytes(bytes):
    __UNSAFE__ = True
    _strip_unsafe = missing_bytes

    def __bytes__(self):
        return self

    def __reduce__(self):
        return type(self), (self._strip_unsafe(),)


class DerivedUnsafeBytes(FixtureUnsafeBytes):
    def __bytes__(self):
        raise AssertionError("the compatibility reducer must use the buffer")

    def decode(self, *args, **kwargs):
        raise AssertionError("the compatibility reducer must not decode bytes")


class ReloadedUnsafeBytes(FixtureUnsafeBytes):
    _strip_unsafe = missing_bytes


class MissingNativeBytes:
    pass


class NativeBytesAvailable:
    __bytes__ = object()


@pytest.fixture(scope="module", autouse=True)
def unload_ansible_after_module():
    yield
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@pytest.fixture
def legacy(monkeypatch):
    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=(3, 10, 21)))
    monkeypatch.setattr(compat, "bytes", MissingNativeBytes, raising=False)
    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", missing_bytes)
    monkeypatch.setattr(ReloadedUnsafeBytes, "_strip_unsafe", missing_bytes)
    modules = {}
    for name in ("ansible", "ansible.release", "ansible.utils", "ansible.utils.unsafe_proxy"):
        module = ModuleType(name)
        module.__path__ = []
        modules[name] = module
        monkeypatch.setitem(sys.modules, name, module)
    modules["ansible.release"].__version__ = "2.15.13"
    modules["ansible.utils.unsafe_proxy"].AnsibleUnsafeBytes = FixtureUnsafeBytes
    return modules


@pytest.mark.parametrize("python_version", [(3, 9, 2), (3, 10, 21)])
@pytest.mark.parametrize("ansible_version", ["2.15.13", "2.15.99", "2.16.0", "2.16.19"])
def test_only_the_known_legacy_failure_is_repaired(legacy, monkeypatch, python_version, ansible_version):
    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=python_version))
    legacy["ansible.release"].__version__ = ansible_version
    reducer = FixtureUnsafeBytes.__reduce__
    converter = FixtureUnsafeBytes.__bytes__

    assert compat.ensure_unsafe_bytes_compatibility() is True
    assert FixtureUnsafeBytes._strip_unsafe is not missing_bytes
    assert FixtureUnsafeBytes._strip_unsafe.__wrapped__ is missing_bytes
    assert FixtureUnsafeBytes._strip_unsafe.__qualname__ == missing_bytes.__qualname__
    assert FixtureUnsafeBytes.__reduce__ is reducer
    assert FixtureUnsafeBytes.__bytes__ is converter
    assert FixtureUnsafeBytes.__UNSAFE__ is True


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
@pytest.mark.parametrize("unsafe_type", [FixtureUnsafeBytes, DerivedUnsafeBytes])
def test_every_pickle_protocol_preserves_bytes_and_the_unsafe_type(legacy, payload, protocol, unsafe_type):
    assert compat.ensure_unsafe_bytes_compatibility()
    value = unsafe_type(payload)

    stripped = value._strip_unsafe()
    restored = pickle.loads(pickle.dumps(value, protocol=protocol))

    assert type(stripped) is bytes
    assert stripped == payload
    assert type(restored) is unsafe_type
    assert restored.__UNSAFE__ is True
    assert memoryview(restored).tobytes() == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_deepcopy_preserves_nested_values_and_unsafe_markers(legacy, payload):
    assert compat.ensure_unsafe_bytes_compatibility()
    original = {
        "value": FixtureUnsafeBytes(payload),
        "nested": [DerivedUnsafeBytes(payload), {"cache": FixtureUnsafeBytes(payload)}],
    }

    restored = copy.deepcopy(original)

    assert restored == original
    assert restored is not original
    assert type(restored["value"]) is FixtureUnsafeBytes
    assert type(restored["nested"][0]) is DerivedUnsafeBytes
    assert type(restored["nested"][1]["cache"]) is FixtureUnsafeBytes
    assert all(value.__UNSAFE__ is True for value in (
        restored["value"], restored["nested"][0], restored["nested"][1]["cache"]))


def test_repeated_calls_leave_the_installed_method_unchanged(legacy):
    assert compat.ensure_unsafe_bytes_compatibility()
    installed = FixtureUnsafeBytes._strip_unsafe

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is installed


def test_a_reloaded_ansible_class_is_checked_again(legacy):
    assert compat.ensure_unsafe_bytes_compatibility()
    first_installed = FixtureUnsafeBytes._strip_unsafe
    legacy["ansible.utils.unsafe_proxy"].AnsibleUnsafeBytes = ReloadedUnsafeBytes

    assert compat.ensure_unsafe_bytes_compatibility()
    assert ReloadedUnsafeBytes._strip_unsafe is not first_installed
    assert ReloadedUnsafeBytes._strip_unsafe.__wrapped__ is missing_bytes
    assert FixtureUnsafeBytes._strip_unsafe is first_installed


def test_different_reloaded_classes_keep_independent_callable_metadata(legacy, monkeypatch):
    def first(value: bytes) -> bytes:
        """The first original method."""
        raise AttributeError(MISSING_BYTES)

    def second(value: bytes) -> bytes:
        """The reloaded original method."""
        raise AttributeError(MISSING_BYTES)

    first.__module__, first.__name__, first.__qualname__ = "first.unsafe_proxy", "_strip_unsafe", "First._strip_unsafe"
    second.__module__, second.__name__, second.__qualname__ = (
        "reloaded.unsafe_proxy", "_strip_unsafe", "Reloaded._strip_unsafe")
    first.custom_metadata, second.custom_metadata = "first", "reloaded"
    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", first)
    monkeypatch.setattr(ReloadedUnsafeBytes, "_strip_unsafe", second)
    attributes = ("__module__", "__name__", "__qualname__", "__doc__", "__annotations__", "custom_metadata")
    first_metadata = {name: getattr(first, name) for name in attributes}
    second_metadata = {name: getattr(second, name) for name in attributes}

    assert compat.ensure_unsafe_bytes_compatibility()
    first_installed = FixtureUnsafeBytes._strip_unsafe
    legacy["ansible.utils.unsafe_proxy"].AnsibleUnsafeBytes = ReloadedUnsafeBytes
    assert compat.ensure_unsafe_bytes_compatibility()
    second_installed = ReloadedUnsafeBytes._strip_unsafe

    assert first_installed is not second_installed
    assert {name: getattr(first_installed, name) for name in attributes} == first_metadata
    assert {name: getattr(second_installed, name) for name in attributes} == second_metadata
    assert {name: getattr(first, name) for name in attributes} == first_metadata
    assert {name: getattr(second, name) for name in attributes} == second_metadata
    assert first_installed.__wrapped__ is first
    assert second_installed.__wrapped__ is second
    assert FixtureUnsafeBytes._strip_unsafe is first_installed
    assert memoryview(FixtureUnsafeBytes(b"\xff\x00")).tobytes() == b"\xff\x00"
    assert first_installed(FixtureUnsafeBytes(b"\xff\x00")) == b"\xff\x00"
    assert second_installed(ReloadedUnsafeBytes(b"\xff\x00")) == b"\xff\x00"


@pytest.mark.parametrize("python_version", [
    (3, 8, 20), (3, 11, 17), (3, 12, 12), (3, 13, 9), (3, 14, 0), (4, 0, 0),
])
def test_other_python_versions_do_not_import_or_change_ansible(legacy, monkeypatch, python_version):
    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=python_version))

    with patch("builtins.__import__", side_effect=AssertionError("Ansible must not be imported")):
        assert compat.ensure_unsafe_bytes_compatibility() is False

    assert FixtureUnsafeBytes._strip_unsafe is missing_bytes


@pytest.mark.parametrize("python_version", [(3, 9, 2), (3, 10, 21)])
def test_native_bytes_capability_prevents_any_ansible_import(legacy, monkeypatch, python_version):
    monkeypatch.setattr(compat, "sys", SimpleNamespace(version_info=python_version))
    monkeypatch.setattr(compat, "bytes", NativeBytesAvailable)

    with patch("builtins.__import__", side_effect=AssertionError("Ansible must not be imported")):
        assert compat.ensure_unsafe_bytes_compatibility() is False

    assert FixtureUnsafeBytes._strip_unsafe is missing_bytes


@pytest.mark.parametrize("version", [
    "2.14.18", "2.17.14", "2.18.19", "2.19.13", "2.20.9", "2.21.4", "3.0.0", "devel",
])
def test_other_ansible_series_are_not_imported_or_changed(legacy, version):
    legacy["ansible.release"].__version__ = version
    original_import = builtins.__import__
    imports = []

    def observed_import(name, *args, **kwargs):
        imports.append(name)
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=observed_import):
        assert compat.ensure_unsafe_bytes_compatibility() is False

    assert "ansible.utils.unsafe_proxy" not in imports
    assert FixtureUnsafeBytes._strip_unsafe is missing_bytes


def test_a_working_backport_is_not_replaced(legacy, monkeypatch):
    def backported(value):
        return memoryview(value).tobytes()

    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", backported)

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is backported


@pytest.mark.parametrize("replacement", [None, b"not a method"])
def test_a_noncallable_method_is_not_replaced(legacy, monkeypatch, replacement):
    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", replacement)

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is replacement


def test_a_missing_method_is_not_added(legacy, monkeypatch):
    monkeypatch.delattr(FixtureUnsafeBytes, "_strip_unsafe")

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert not hasattr(FixtureUnsafeBytes, "_strip_unsafe")


@pytest.mark.parametrize("qualified_name", [None, 42], ids=["absent", "invalid"])
def test_a_callable_without_normal_qualified_name_metadata_is_not_replaced(legacy, monkeypatch, qualified_name):
    class NonstandardCallable:
        calls = 0

        def __call__(self, value):
            self.calls += 1
            raise AttributeError(MISSING_BYTES)

    original = NonstandardCallable()
    if qualified_name is not None:
        original.__qualname__ = qualified_name
    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", original)

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is original
    assert original.calls == 0


class OtherAttributeError(AttributeError):
    pass


@pytest.mark.parametrize("error", [
    AttributeError("an unrelated attribute is missing"),
    AttributeError(MISSING_BYTES, "additional context"),
    OtherAttributeError(MISSING_BYTES),
    TypeError(MISSING_BYTES),
    ValueError(MISSING_BYTES),
    RuntimeError(MISSING_BYTES),
])
def test_an_unrelated_method_failure_is_not_replaced(legacy, monkeypatch, error):
    def unrelated(value):
        raise error

    monkeypatch.setattr(FixtureUnsafeBytes, "_strip_unsafe", unrelated)

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is unrelated


def test_a_constructor_failure_is_not_treated_as_the_reducer_failure(legacy):
    class ConstructorFailure:
        _strip_unsafe = missing_bytes

        def __init__(self, value):
            raise AttributeError(MISSING_BYTES)

    legacy["ansible.utils.unsafe_proxy"].AnsibleUnsafeBytes = ConstructorFailure

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert ConstructorFailure._strip_unsafe is missing_bytes


@pytest.mark.parametrize("missing_module", ["ansible.release", "ansible.utils.unsafe_proxy"])
def test_absent_optional_ansible_modules_are_ignored(legacy, monkeypatch, missing_module):
    monkeypatch.setitem(sys.modules, missing_module, None)

    assert compat.ensure_unsafe_bytes_compatibility() is False
    assert FixtureUnsafeBytes._strip_unsafe is missing_bytes


def test_the_standalone_module_loads_without_ansible_or_site_packages(tmp_path):
    source = str(Path(compat.__file__).resolve())
    script = (
        "import runpy, sys; namespace = runpy.run_path({!r}); "
        "assert namespace['ensure_unsafe_bytes_compatibility']() is False; "
        "assert not any(name.startswith('ansible') for name in sys.modules)"
    ).format(source)

    result = subprocess.run(
        [sys.executable, "-S", "-c", script], cwd=str(tmp_path),
        capture_output=True, text=True, timeout=15, check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_common_constructor_refreshes_compatibility_before_reading_configuration(monkeypatch):
    package = importlib.import_module("keeper_secrets_manager_ansible")

    def observed():
        raise RuntimeError("compatibility was refreshed")

    monkeypatch.setattr(package, "_ensure_unsafe_bytes_compatibility", observed)

    with pytest.raises(RuntimeError, match="^compatibility was refreshed$"):
        package.KeeperAnsible({})


TEMPLATE_GUARD_SCRIPT = r'''
import json
import sys

from ansible.release import __version__
from ansible.utils.unsafe_proxy import AnsibleUnsafeBytes, AnsibleUnsafeText

unsafe_class = AnsibleUnsafeBytes
original = getattr(unsafe_class, "_strip_unsafe", None)
original_text = getattr(AnsibleUnsafeText, "_strip_unsafe", None)
original_reduce = unsafe_class.__reduce__
original_bytes = getattr(unsafe_class, "__bytes__", None)
attributes = ("__module__", "__name__", "__qualname__", "__doc__", "__annotations__")
metadata = {name: getattr(original, name) for name in attributes} if original is not None else None
template_first = sys.argv[1] == "template-first"
templar = None


def observed_template(templar, template_module):
    source = "{{ value._strip_unsafe() }}"
    trust = getattr(template_module, "trust_as_template", None)
    if trust is not None:
        source = trust(source)
    try:
        templar.template(source)
    except Exception as error:
        return {"allowed": False, "error_type": type(error).__name__}
    return {"allowed": True, "error_type": None}


if template_first:
    import ansible.template as template_module
    from ansible.parsing.dataloader import DataLoader
    templar = template_module.Templar(loader=DataLoader(), variables={"value": unsafe_class(b"synthetic")})
    before = observed_template(templar, template_module)

import keeper_secrets_manager_ansible
import ansible.template as template_module
from ansible.parsing.dataloader import DataLoader
from ansible.utils.unsafe_proxy import AnsibleUnsafeBytes

patched = getattr(AnsibleUnsafeBytes, "_strip_unsafe", None)
legacy = sys.version_info[:2] in ((3, 9), (3, 10)) and not hasattr(bytes, "__bytes__")
affected = legacy and __version__.split(".")[:2] in (["2", "15"], ["2", "16"])
assert AnsibleUnsafeBytes is unsafe_class
assert AnsibleUnsafeBytes.__reduce__ is original_reduce
assert getattr(AnsibleUnsafeBytes, "__bytes__", None) is original_bytes
assert getattr(AnsibleUnsafeText, "_strip_unsafe", None) is original_text
assert (patched is not original) is affected
if original is not None:
    assert {name: getattr(patched, name) for name in attributes} == metadata
    assert patched.__qualname__ in template_module.AnsibleContext._disallowed_callables
    if affected:
        assert patched.__wrapped__ is original
if templar is None:
    templar = template_module.Templar(loader=DataLoader(), variables={"value": unsafe_class(b"synthetic")})
after = observed_template(templar, template_module)
assert not after["allowed"], after
if original is not None:
    assert after["error_type"] == "SecurityError", after
if template_first:
    assert before == after, (before, after)
print(json.dumps({
    "python": list(sys.version_info[:3]), "ansible": __version__,
    "import_order": sys.argv[1], "patch_applied": patched is not original, "after": after,
}))
'''


@pytest.mark.parametrize("import_order", ["template-first", "keeper-first"])
def test_fresh_processes_preserve_the_template_callable_guard(tmp_path, import_order):
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n", encoding="utf-8")
    env = dict(os.environ, HOME=str(tmp_path), ANSIBLE_CONFIG=str(config),
               PYTHONPATH=str(Path(compat.__file__).resolve().parents[1]), PYTHONDONTWRITEBYTECODE="1")

    result = subprocess.run(
        [sys.executable, "-c", TEMPLATE_GUARD_SCRIPT, import_order],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=20, check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["import_order"] == import_order
    assert observed["after"]["allowed"] is False


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_real_ansible_bytes_keep_their_native_type_and_unsafe_marker(payload, protocol):
    unsafe_proxy = importlib.import_module("ansible.utils.unsafe_proxy")
    unsafe_type = unsafe_proxy.AnsibleUnsafeBytes
    if not hasattr(unsafe_type, "_strip_unsafe"):
        pytest.skip("this engine uses native tagged values instead of the legacy unsafe bytes class")
    compat.ensure_unsafe_bytes_compatibility()
    value = unsafe_type(payload)

    restored = pickle.loads(pickle.dumps(value, protocol=protocol))
    copied = copy.deepcopy({"value": value})["value"]

    assert type(restored) is unsafe_type
    assert type(copied) is unsafe_type
    assert restored.__UNSAFE__ is True
    assert copied.__UNSAFE__ is True
    assert memoryview(restored).tobytes() == payload
    assert memoryview(copied).tobytes() == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_real_ansible_bytes_remain_supported_by_the_yaml_dumper(payload):
    unsafe_proxy = importlib.import_module("ansible.utils.unsafe_proxy")
    unsafe_type = unsafe_proxy.AnsibleUnsafeBytes
    if not hasattr(unsafe_type, "_strip_unsafe"):
        pytest.skip("this engine uses native tagged values instead of the legacy unsafe bytes class")
    compat.ensure_unsafe_bytes_compatibility()
    dumper = importlib.import_module("ansible.parsing.yaml.dumper").AnsibleDumper
    yaml = importlib.import_module("yaml")
    value = unsafe_type(payload)

    restored = yaml.safe_load(yaml.dump({"value": value}, Dumper=dumper))

    assert restored == {"value": payload}
    assert type(restored["value"]) is bytes
    assert value.__UNSAFE__ is True
