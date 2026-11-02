import importlib
import os
import shutil
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

import keeper_secrets_manager_ansible.plugins

from ..ansible_test_framework import AnsibleTestFramework

COMPONENT_DIR = Path(__file__).resolve().parents[2]
RUNTIME_YML = COMPONENT_DIR / "ansible_galaxy/keepersecurity/keeper_secrets_manager/meta/runtime.yml"
PLUGINS_DIR = Path(keeper_secrets_manager_ansible.plugins.__file__).parent


def unload_ansible():
    """Each run needs a fresh loader, initialized after its plugin and collection paths are set."""
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)


@contextmanager
def _environment(name, value):
    saved = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = saved


@contextmanager
def _collection_path():
    """Expose the real action group metadata and plugins without copying the plugin tree."""
    with tempfile.TemporaryDirectory(prefix="ksm_target_collections_") as root:
        collection = Path(root) / "ansible_collections/keepersecurity/keeper_secrets_manager"
        (collection / "meta").mkdir(parents=True)
        (collection / "plugins").mkdir()
        shutil.copyfile(RUNTIME_YML, collection / "meta/runtime.yml")
        try:
            for name in ("action", "modules"):
                (collection / "plugins" / name).symlink_to(PLUGINS_DIR / name)
            with _environment("ANSIBLE_COLLECTIONS_PATH", root):
                yield
        finally:
            # Unlink first, so cleanup cannot reach the real plugin files.
            for name in ("action", "modules"):
                link = collection / "plugins" / name
                if link.is_symlink():
                    link.unlink()


@contextmanager
def _vault_password(password):
    # mkstemp makes a private, non-executable file. Ansible executes executable password files.
    fd, filename = tempfile.mkstemp(prefix="ksm_target_vault_", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(password + "\n")
        with _environment("ANSIBLE_VAULT_PASSWORD_FILE", filename):
            yield
    finally:
        os.remove(filename)


@contextmanager
def run_target(server, target, variables, collection=False, vault_password=None, sdk_patch=None):
    """Run once per module, retain server state for assertions, and clean up when the fixture ends."""
    unload_ansible()
    try:
        with ExitStack() as stack:
            if collection:
                stack.enter_context(_collection_path())
            if vault_password is not None:
                stack.enter_context(_vault_password(vault_password))
            stack.enter_context(server.patch())
            if sdk_patch is not None:
                stack.enter_context(sdk_patch)
            # Import after staging collections: Display initializes Ansible's plugin paths.
            errors = importlib.import_module("ansible.errors")
            display = importlib.import_module("ansible.utils.display").Display()
            stack.enter_context(patch("keeper_secrets_manager_ansible.AnsibleError", errors.AnsibleError))
            stack.enter_context(patch("keeper_secrets_manager_ansible.display", display))
            result = AnsibleTestFramework(playbook=target, vars=variables).run()
        yield result
    finally:
        server.cleanup()
        unload_ansible()
