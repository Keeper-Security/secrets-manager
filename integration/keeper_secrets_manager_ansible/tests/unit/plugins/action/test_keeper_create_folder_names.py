import json
import sys
from textwrap import indent

import pytest
import yaml
from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

from ....folder_fake_server import FakeKeeperServer


PLUGIN = "keeper_create_folder"
SHARED, NESTED = "SHARED_UID", "NESTED_UID"
BLANK = "The folder_name is blank. keeper_create_folder requires this value to be set."
NOT_TEXT = ("The folder_name option must be a string, but it is {}. Put quotes around the value, or use the "
            "string filter.")
PADDED = ("The folder_name {!r} has leading or trailing whitespace. Remove it. In YAML, a block scalar (| or >) "
          "keeps the newline at its end.")


@pytest.fixture(scope="module", autouse=True)
def unload_create_plugin():
    # Ansible is unloaded between modules; do not retain its old exception class in the action.
    yield
    sys.modules.pop("keeper_secrets_manager_ansible.plugins.action." + PLUGIN, None)


@pytest.fixture
def name_loader(monkeypatch):
    def load(text, vaulted=False):
        if not vaulted:
            return yaml.safe_load(json.dumps(text))
        from ansible.parsing.dataloader import DataLoader
        from ansible.parsing import vault
        secret = vault.VaultSecret(b"folder-name-test-only")
        secrets = [("default", secret)]
        encrypted = vault.VaultLib(secrets).encrypt(text.encode(), secret=secret).decode()
        loader = DataLoader()
        loader.set_vault_secrets(secrets)
        if hasattr(vault, "VaultSecretsContext"):
            monkeypatch.setattr(vault.VaultSecretsContext, "_current", vault.VaultSecretsContext(secrets))
        return loader.load("folder_name: !vault |\n" + indent(encrypted, "  "))["folder_name"]
    return load


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("source, message", [
    pytest.param("No", NOT_TEXT.format("a boolean (False)"), id="yaml_false"),
    pytest.param("true", NOT_TEXT.format("a boolean (True)"), id="yaml_true"),
    pytest.param("0", NOT_TEXT.format("a number (0)"), id="yaml_zero"),
    pytest.param("2024", NOT_TEXT.format("a number (2024)"), id="yaml_year"),
    pytest.param("[No]", NOT_TEXT.format("a list"), id="yaml_list"),
    pytest.param("{name: No}", NOT_TEXT.format("a dictionary"), id="yaml_dict"),
    pytest.param("null", "The folder_name option is null. Give it a value, or leave the option out of the task.",
                 id="null"),
    pytest.param("''", BLANK, id="empty"),
    pytest.param('" \\t\\r\\n "', BLANK, id="whitespace"),
    pytest.param("!vault", BLANK, id="vault_whitespace"),
])
def test_invalid_names_fail_before_client_initialization(
        make_sdk, run_plugin, name_loader, check_mode, source, message):
    value = (name_loader(" \t\r\n ", vaulted=True) if source == "!vault"
             else yaml.safe_load("folder_name: " + source)["folder_name"])
    sdk = make_sdk([])
    result = run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": value}, check_mode=check_mode)
    assert result == {"failed": True, "changed": False, "msg": message}
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("vaulted", [False, True], ids=["quoted", "inline_vault"])
@pytest.mark.parametrize("name", [
    pytest.param(" Padded ", id="padded_nonblank"),
    pytest.param(" New", id="leading_space"),
    pytest.param("New ", id="trailing_space"),
    pytest.param("\tNew", id="leading_tab"),
    pytest.param("New\t", id="trailing_tab"),
    pytest.param("\nNew", id="leading_newline"),
    pytest.param("New\n", id="trailing_newline"),
    pytest.param("New\r", id="trailing_carriage_return"),
    pytest.param("New\r\n", id="trailing_crlf"),
    pytest.param("\u00a0New", id="leading_unicode_whitespace"),
    pytest.param("New\u2003", id="trailing_unicode_whitespace"),
    pytest.param("Bob's folder ", id="quoted_diagnostic"),
])
def test_padded_names_fail_before_client_initialization(
        make_sdk, run_plugin, name_loader, check_mode, name, vaulted):
    sdk = make_sdk([])
    result = run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": name_loader(name, vaulted)},
                        check_mode=check_mode)
    assert result == {"failed": True, "changed": False, "msg": PADDED.format(name)}
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("scalar", ["|", ">"], ids=["literal", "folded"])
def test_yaml_block_scalar_newline_fails_before_client_initialization(make_sdk, run_plugin, scalar, check_mode):
    name = yaml.safe_load("folder_name: {}\n  Foo\n".format(scalar))["folder_name"]
    assert name == "Foo\n"
    sdk = make_sdk([])
    result = run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": name}, check_mode=check_mode)
    assert result == {"failed": True, "changed": False, "msg": PADDED.format(name)}
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
@pytest.mark.parametrize("parent", [SHARED, NESTED], ids=["shared", "nested"])
def test_existing_padded_name_still_fails_before_client_initialization(
        make_sdk, folder, run_plugin, parent, check_mode):
    sdk = make_sdk([folder("EXISTING_UID", parent, "Existing ")])
    args = {"shared_folder_uid": SHARED, "folder_name": "Existing "}
    if parent == NESTED:
        args["subfolder_uid"] = NESTED
    assert run_plugin(sdk, args, check_mode=check_mode) == {
        "failed": True, "changed": False, "msg": PADDED.format("Existing "),
    }
    assert sdk.inits == 0
    assert sdk.client.mock_calls == []


@pytest.mark.parametrize("check_mode", [False, True], ids=["normal", "check"])
def test_unsupported_option_fails_before_client_initialization(make_sdk, run_plugin, check_mode):
    sdk = make_sdk([])
    result = run_plugin(sdk, {"shared_folder_uid": SHARED, "folder_name": "New", "folder_nmae": "Other"},
                        check_mode=check_mode)
    assert result["failed"] is True and result["changed"] is False
    assert result["msg"].startswith("Unsupported parameters for (keeper_create_folder) module: folder_nmae.")
    assert sdk.inits == 0 and sdk.client.mock_calls == []


@pytest.fixture
def encrypted_server():
    server = FakeKeeperServer([
        {"uid": SHARED, "name": "Shared", "parent": None},
        {"uid": NESTED, "name": "Nested", "parent": SHARED},
    ])
    try:
        with server.patch():
            yield server
    finally:
        server.cleanup()


def no_network(*args, **kwargs):
    pytest.fail("An offline folder test attempted an unmocked network request")


@pytest.mark.parametrize("parent", [None, NESTED], ids=["shared", "nested"])
@pytest.mark.parametrize("name, vaulted", [
    pytest.param("No", False, id="quoted_false"),
    pytest.param("0", False, id="quoted_zero"),
    pytest.param("2024", False, id="quoted_year"),
    pytest.param("Inner  spaces", False, id="inner_spaces"),
    pytest.param("Inner\ttab", False, id="inner_tab"),
    pytest.param("Inner\nnewline", False, id="inner_newline"),
    pytest.param(yaml.safe_load("|-\n  Literal\n"), False, id="literal_strip"),
    pytest.param(yaml.safe_load(">-\n  Folded\n  name\n"), False, id="folded_strip"),
    pytest.param("Vaulted Name", True, id="inline_vault"),
])
def test_real_sdk_preserves_names_and_repeated_creation_is_idempotent(
        encrypted_server, make_sdk, run_plugin, name_loader, parent, name, vaulted):
    sdk = make_sdk([])
    sdk.client = SecretsManager(config=InMemoryKeyValueStorage(mock.MockConfig.make_base64()))
    sdk.client.post_function = no_network
    sdk.client.custom_post_function = None
    args = {"shared_folder_uid": SHARED, "folder_name": name_loader(name, vaulted)}
    if parent is not None:
        args["subfolder_uid"] = parent
    assert run_plugin(sdk, args, check_mode=True) == {"changed": True, "folder_uid": None}
    assert encrypted_server.calls("create_folder") == []
    first = run_plugin(sdk, args)
    assert first["changed"] is True
    assert isinstance(first["folder_uid"], str) and first["folder_uid"]
    for check_mode in (True, False):
        assert run_plugin(sdk, args, check_mode=check_mode) == {
            "changed": False, "folder_uid": first["folder_uid"],
        }
    creates = encrypted_server.calls("create_folder")
    assert len(creates) == 1
    created = creates[0]
    assert (created["folder_name"], created["shared_folder_uid"], created["parent_uid"]) == (name, SHARED, parent)
    assert type(creates[0]["folder_name"]) is str
    decoded = next(folder for folder in sdk.client.get_folders() if folder.folder_uid == first["folder_uid"])
    assert decoded.name == name and type(decoded.name) is str
    assert encrypted_server.folder(first["folder_uid"]) == {
        "uid": first["folder_uid"], "name": name, "parent": parent or SHARED,
    }
