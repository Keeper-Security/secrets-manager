# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ansible.utils.display import Display
from ansible.errors import AnsibleError
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import jsonify
import os
import sys
import re
import json
import random
from enum import Enum
import traceback
import base64
import socket
import datetime
import logging

# Check if the KSM SDK core has been installed
KSM_SDK_ERR = None
try:
    import keeper_secrets_manager_core
except ImportError:
    KSM_SDK_ERR = traceback.format_exc()
else:
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.core import KSMCache, CreateOptions
    from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
    from keeper_secrets_manager_core.utils import generate_password as sdk_generate_password, strtobool
    from keeper_secrets_manager_core.dto.dtos import Record as _Record, KeeperFile as _KeeperFile

    # If keeper_secrets_manager_core is installed, then these will be installed. They are deps.
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


display = Display()


class CacheUnusableError(ValueError):
    """Encrypted record cache cannot be decrypted or deserialized; treat as a cache miss."""


class KeeperFolderError(Exception):
    """A folder lookup, rename, or delete cannot complete as asked. The message is written for the playbook author."""


class KeeperArgumentError(ValueError):
    """The options of a task are not valid. The message is written for the playbook author."""


class _UnreadableFolderLog(logging.Handler):
    """
    Collect the folders that the SDK skips while it reads the folder list, as {folder UID: error text}.

    keeper-secrets-manager-core 17.4.0 and later skip a folder that they cannot decrypt, for example a folder in a
    newer format, and only log a warning. So a folder that exists can be missing from get_folders().
    """

    def __init__(self):
        super(_UnreadableFolderLog, self).__init__(level=logging.WARNING)
        self.folders = {}

    def emit(self, record):
        try:
            if "skipped due to error" in str(record.msg) and isinstance(record.args, tuple) and record.args:
                self.folders[str(record.args[0])] = str(record.args[1]) if len(record.args) > 1 else ""
        except Exception:
            pass


class KeeperFieldType(Enum):
    FIELD = "field"
    CUSTOM_FIELD = "custom_field"
    FILE = "file"
    NOTES = "notes"

    @staticmethod
    def get_enum(value):
        for e in KeeperFieldType:
            if e.value == value:
                return e
        return None


class KeeperAnsible:
    """ A class containing a common method used by the Ansible plugin and also talked to Keeper Python SDK
    """

    KEY_PREFIX = "keeper"
    KEY_CONFIG_FILE_SUFFIX = "config_file"
    KEY_CONFIG_BASE64 = "config"
    ALLOWED_FIELDS = ["field", "custom_field", "file", "notes"]
    TOKEN_ENV = "KSM_TOKEN"
    TOKEN_KEY = "token"
    HOSTNAME_KEY = "hostname"
    CONFIG_CLIENT_KEY = "clientKey"
    FORCE_CONFIG_FILE = "force_config_write"
    KEY_SSL_VERIFY_SKIP = "verify_ssl_certs_skip"
    KEY_LOG_LEVEL = "log_level"
    KEY_USE_CACHE = "use_cache"
    KEY_CACHE_DIR = "cache_dir"
    ENV_CACHE_DIR = "KSM_CACHE_DIR"
    DEFAULT_LOG_LEVEL = "ERROR"
    REDACT_MODULE_MATCH = r"\.keeper_redact$"
    ACTION_GROUP_PREFIX = "group/keepersecurity.keeper_secrets_manager."

    @staticmethod
    def get_client(**kwargs):
        return SecretsManager(**kwargs)

    @staticmethod
    def keeper_key(key):
        return "{}_{}".format(KeeperAnsible.KEY_PREFIX, key)

    @staticmethod
    def fail_json(msg, **kwargs):
        kwargs['failed'] = True
        kwargs['msg'] = msg
        print('\n%s' % jsonify(kwargs))
        sys.exit(0)

    @staticmethod
    def _vault_string_types():
        # A value that Ansible Vault encrypts in the playbook (!vault) is not a str, but str() gives the decrypted
        # text, so it is a string value. The class is EncryptedString in ansible-core 2.19 and later, and
        # AnsibleVaultEncryptedUnicode before that. The new name is tried first, because the old one is deprecated.
        try:
            from ansible.parsing.vault import EncryptedString
            return (EncryptedString,)
        except ImportError:
            pass
        try:
            from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
            return (AnsibleVaultEncryptedUnicode,)
        except ImportError:
            return ()

    @staticmethod
    def _is_text(value):
        # Only a string, or a string that Ansible Vault encrypts, is text. YAML turns some values that have no quotes
        # into other types, and str() of them does not always give back the text that the playbook author wrote:
        # 010 becomes 8, 007 becomes 7, 1.10 becomes 1.1, and yes becomes True. A list or a dictionary is never a
        # name or a UID.
        return isinstance(value, str) or isinstance(value, KeeperAnsible._vault_string_types())

    @staticmethod
    def _describe_value(value):
        if isinstance(value, bool):
            return "a boolean ({})".format(value)
        if isinstance(value, (int, float)):
            return "a number ({})".format(value)
        if isinstance(value, datetime.datetime):
            return "a date and time ({})".format(value)
        if isinstance(value, datetime.date):
            return "a date ({})".format(value)
        if isinstance(value, dict):
            return "a dictionary"
        if isinstance(value, (list, tuple, set, frozenset)):
            return "a list"
        if isinstance(value, (bytes, bytearray)):
            return "a byte string"
        return "a value of type {}".format(type(value).__name__)

    @staticmethod
    def _join_messages(messages):
        # A space after a message that ends with a period, else a semicolon.
        text = ""
        for message in messages:
            if text:
                text += " " if text.endswith(".") else "; "
            text += message
        return text

    @staticmethod
    def validate_task_args(module_name, task_args, argument_spec, mutually_exclusive=None, ignore=None):
        """
        Check task arguments against an argument spec and return the validated arguments. Raise
        KeeperArgumentError if they are not valid.

        Unknown (for example misspelled) options are rejected instead of silently ignored, values are
        converted to their declared type, and defaults are filled in. An option that is set to null is an error,
        and so is a str option whose value is not a string (see _is_text). The option names in ignore are removed
        first if the module does not have them (see group_default_options).

        This calls ArgumentSpecValidator directly because ActionBase.validate_argument_spec needs ansible-core
        2.13, and this package supports ansible-core 2.12.
        """
        # Imported here, not at the top of the module: ArgumentSpecValidator needs ansible-core 2.11, and only the
        # modules that validate their arguments must need it. Every other module keeps working on older Ansible.
        from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
        from ansible.module_utils.errors import UnsupportedError

        ignore = set(ignore or [])
        # group_default_options gives names as text, so compare the text of each option name.
        task_args = {k: v for k, v in dict(task_args).items() if k in argument_spec or str(k) not in ignore}

        # An option name must be a string. YAML reads an unquoted key such as 1 as a number.
        not_names = sorted(repr(k) for k in task_args if not isinstance(k, str))
        if not_names:
            raise KeeperArgumentError("Unsupported parameters for ({}) module: {}. An option name must be a "
                                      "string.".format(module_name, ", ".join(not_names)))

        # A template variable with no value gives null. If null meant "not set", a lookup would silently start
        # from a different folder, for example the shared folder instead of a subfolder. ArgumentSpecValidator
        # also turns any value of a str option into a string, with no warning: a list becomes "['a', 'b']", yes
        # becomes "True", and 1.10 becomes "1.1". For a UID or a folder name, that is a different value.
        messages = []
        for name in sorted(task_args):
            value = task_args[name]
            if name not in argument_spec:
                continue
            if value is None:
                # The hint names no filter on purpose. default(omit) does not leave out a variable that is set to
                # null, and default(omit, true) also leaves out an empty string, which turns off the blank check and
                # can make a lookup silently return its start folder.
                messages.append("The {} option is null. Give it a value, or leave the option out of the "
                                "task.".format(name))
            elif argument_spec[name].get("type") == "str" and not KeeperAnsible._is_text(value):
                messages.append("The {} option must be a string, but it is {}. Put quotes around the value, or use "
                                "the string filter.".format(name, KeeperAnsible._describe_value(value)))
        if messages:
            raise KeeperArgumentError(KeeperAnsible._join_messages(messages))

        validator = ArgumentSpecValidator(argument_spec, mutually_exclusive=mutually_exclusive)
        result = validator.validate(task_args)
        if result.error_messages:
            for error in result.errors.errors:
                if isinstance(error, UnsupportedError):
                    messages.append("Unsupported parameters for ({}) module: {}".format(module_name, error.msg))
                else:
                    messages.append(error.msg)
            raise KeeperArgumentError(KeeperAnsible._join_messages(messages))
        return result.validated_parameters

    @staticmethod
    def group_default_options(task, templar=None):
        """
        Get the option names that module_defaults sets for an action group, for the task of an action plugin.

        Ansible gives the defaults of a group to every module in the group, so a group default can hold options
        that only some modules of the group have. validate_task_args ignores these names for a module that does
        not have them. A misspelled option in the task itself still fails, unless a group default has the same
        name.

        Only the groups of this collection are read. Ansible gives a group default only to the modules in that
        group, so the defaults of another collection's group never reach these modules, and their option names
        must not hide a mistake in a task.
        """
        names = set()
        module_defaults = getattr(task, "module_defaults", None) or []
        if isinstance(module_defaults, dict):
            module_defaults = [module_defaults]
        for defaults in module_defaults:
            if not isinstance(defaults, dict):
                continue
            for entry, values in defaults.items():
                if not str(entry).startswith(KeeperAnsible.ACTION_GROUP_PREFIX):
                    continue
                if isinstance(values, str) and templar is not None:
                    try:
                        values = templar.template(values)
                    except Exception:
                        values = None
                if isinstance(values, dict):
                    names.update(str(k) for k in values)
        return names

    def __init__(self, task_vars, action_module=None, task_attributes=None, force_in_memory=False):

        """
        Build the config used by the Keeper Python SDK

        The configuration is mainly read from a JSON file.

        """

        if KSM_SDK_ERR is not None:
            self.fail_json(msg=missing_required_lib('keeper-secrets-manager-core'), exception=KSM_SDK_ERR)

        # These are the variables set in playbook, host, group, ansible secret.
        self.task_vars = task_vars

        # This is an instance of ActionModule
        self.action_module = action_module

        # These are the attributes of the task or kwargs of a lookup action
        if task_attributes is None:
            if self.action_module is not None and hasattr(action_module, "_task"):
                task = getattr(self.action_module, "_task")
                task_attributes = task.args
            else:
                task_attributes = {}
        self.task_attributes = task_attributes

        self.config_file = None
        self.config_created = False
        self.using_cache = False

        # Check if we have the keeper redact callback stdout plugin is enabled.
        self.has_redact = False
        for module in sys.modules:
            if re.search(KeeperAnsible.REDACT_MODULE_MATCH, module) is not None:
                self.has_redact = True
                break

        self.secret_values = []

        def camel_case(text):
            text = re.sub(r"([_\-])+", " ", text).title().replace(" ", "")
            return text[0].lower() + text[1:]

        try:
            # Match the SDK log level to Ansible log level
            log_level_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_LOG_LEVEL)
            log_level = task_vars.get(log_level_key, KeeperAnsible.DEFAULT_LOG_LEVEL)

            # Else try is give logging level based on the Ansible display level
            if display.verbosity == 1:
                # -v
                log_level = "INFO"
            elif display.verbosity >= 3:
                # -vvv
                log_level = "DEBUG"

            keeper_config_file_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_CONFIG_FILE_SUFFIX)
            keeper_ssl_verify_skip = KeeperAnsible.keeper_key(KeeperAnsible.KEY_SSL_VERIFY_SKIP)

            # By default, we don't want to skip verify the certs.
            ssl_certs_skip = task_vars.get(keeper_ssl_verify_skip, False)

            # If the config location is defined, or a file exists at the default location.
            self.config_file = self._template_value(task_vars.get(keeper_config_file_key))
            if self.config_file is None:
                self.config_file = FileKeyValueStorage.default_config_file_location

            # Should we be using the cache?
            use_cache_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_USE_CACHE)
            custom_post_function = None
            if bool(strtobool(str(task_vars.get(use_cache_key, "False")))) is True:
                custom_post_function = KSMCache.caching_post_function

                # We are using the cache, what directory should the cache file be stored in.
                cache_dir_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_CACHE_DIR)
                cache_dir_val = self._template_value(task_vars.get(cache_dir_key))
                if cache_dir_val is not None and os.environ.get(KeeperAnsible.ENV_CACHE_DIR) is None:
                    os.environ[KeeperAnsible.ENV_CACHE_DIR] = cache_dir_val
                    # Update the cache file path after setting the environment variable
                    KSMCache.kms_cache_file_name = os.path.join(os.environ.get(KeeperAnsible.ENV_CACHE_DIR, ""), 'ksm_cache.bin')

                display.vvv("Keeper Secrets Manager is using DR file cache. Cache directory is {}.".format(
                    os.environ.get(KeeperAnsible.ENV_CACHE_DIR)
                    if os.environ.get(KeeperAnsible.ENV_CACHE_DIR) is not None else "current working directory"))

                self.using_cache = True
            else:
                display.vvv("Keeper Secrets Manager is not using a DR file cache.")

            if os.path.isfile(self.config_file) is True and force_in_memory is False:
                display.vvv("Loading keeper config file file {}.".format(self.config_file))
                self.client = KeeperAnsible.get_client(
                    config=FileKeyValueStorage(config_file_location=self.config_file),
                    log_level=log_level,
                    custom_post_function=custom_post_function
                )

            # Else config values in the Ansible variable.
            else:
                display.vvv("Loading keeper config from Ansible vars.")

                # Since we are getting our variables from Ansible, we want to default using the in memory storage so
                # not to leave config files lying around.
                in_memory_storage = True

                # If we have a parameter with a Base64 config, use it for the config_option and force
                # the config to be in memory.

                base64_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_CONFIG_BASE64)
                if base64_key in task_vars:
                    config_option = task_vars.get(base64_key)
                    force_in_memory = True
                # Else try to discover the config values.
                else:

                    # Config is not a Base64 string, make a dictionary to hold config values.
                    config_option = {}
                    # Convert Ansible variables into the keys used by Secrets Manager's config.
                    for key in ["url", "client_id", "client_key", "app_key", "private_key", "bat", "binding_key",
                                "hostname", "server_public_key_id", "app_owner_public_key"]:
                        keeper_key = KeeperAnsible.keeper_key(key)
                        camel_key = camel_case(key)
                        if keeper_key in task_vars:
                            config_option[camel_key] = task_vars[keeper_key]

                    # The token is the odd ball.
                    # We need it to be client key in the SDK config.
                    # SDK will remove it when it is done.
                    token_key = KeeperAnsible.keeper_key(KeeperAnsible.TOKEN_KEY)
                    if token_key in task_vars:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = task_vars[token_key]

                    # If the secret client key is in the environment, override the Ansible var.
                    if os.environ.get(KeeperAnsible.TOKEN_ENV) is not None:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = os.environ.get(KeeperAnsible.TOKEN_ENV)
                    elif token_key in task_vars:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = task_vars[token_key]

                    # If no variables were passed in, throw an error.
                    if len(config_option) == 0:
                        raise AnsibleError("There is no config file and the Ansible variable contain no config keys."
                                           " Will not be able to connect to the Keeper server.")

                    # Does the user want to write the config to a file? Then don't use the in memory storage.
                    if bool(task_vars.get(KeeperAnsible.keeper_key(KeeperAnsible.FORCE_CONFIG_FILE), False)) is True:
                        in_memory_storage = False
                    # If the is only 1 key, we want to force the config to write to the file.
                    elif len(config_option) == 1 and KeeperAnsible.CONFIG_CLIENT_KEY in config_option:
                        in_memory_storage = False

                # Sometimes we don't want a JSON file, ever. Force the config to be in memory.
                if force_in_memory is True:
                    in_memory_storage = True

                if in_memory_storage is True:
                    config_instance = InMemoryKeyValueStorage(config=config_option)
                else:
                    if self.config_file is None:
                        self.config_file = FileKeyValueStorage.default_config_file_location
                        self.config_created = True
                    elif os.path.isfile(self.config_file) is False:
                        self.config_created = True

                    # Write the variables we have to a JSON file.
                    # If we are in here, config_option is a dictionary,
                    # not a Base64 string.
                    with open(self.config_file, "w") as fh:
                        json.dump(config_option, fh, indent=4)
                        fh.close()

                    config_instance = FileKeyValueStorage(config_file_location=self.config_file)
                    config_instance.read_storage()

                self.client = KeeperAnsible.get_client(
                    config=config_instance,
                    verify_ssl_certs=not ssl_certs_skip,
                    log_level=log_level,
                    custom_post_function=custom_post_function
                )

        except Exception as err:
            raise AnsibleError("Keeper Ansible error: {}".format(err))

    def _template_value(self, value):
        """Resolve Jinja2 expressions in a task_vars value using Ansible's templar."""
        if value is not None and self.action_module is not None and hasattr(self.action_module, '_templar'):
            value = self.action_module._templar.template(value)
        return value

    def get_encryption_key(self):

        cache_secret = self.task_vars.get("keeper_record_cache_secret")
        if cache_secret is None:
            raise ValueError("The keeper_record_cache_secret is blank. In order to encrypt the cache, "
                             "keeper_record_cache_secret needs to be set in task, group, host or vault variables.")

        # Needs something for the salt, it needs to be 32 bytes long.
        salt = socket.gethostname().zfill(32)[0:32]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=390000,
        )

        return base64.urlsafe_b64encode(kdf.derive(cache_secret.encode()))

    @staticmethod
    def _file_to_dict(keeper_file):
        """Serialize a KeeperFile instance to a JSON-safe dictionary."""
        d = {
            "name": keeper_file.name,
            "title": keeper_file.title,
            "type": keeper_file.type,
            "last_modified": keeper_file.last_modified,
            "size": keeper_file.size,
            "f": keeper_file.f,
            "file_key": keeper_file.file_key,
            "meta_dict": keeper_file.meta_dict,
        }
        d["record_key_bytes"] = base64.b64encode(keeper_file.record_key_bytes).decode("ascii") \
            if keeper_file.record_key_bytes is not None else None
        d["file_data"] = base64.b64encode(keeper_file.file_data).decode("ascii") \
            if keeper_file.file_data is not None else None
        return d

    @staticmethod
    def _file_from_dict(d):
        """Reconstruct a KeeperFile instance from a JSON-deserialized dictionary."""
        f = object.__new__(_KeeperFile)
        f.name = d["name"]
        f.title = d["title"]
        f.type = d["type"]
        f.last_modified = d["last_modified"]
        f.size = d["size"]
        f.f = d["f"]
        f.file_key = d["file_key"]
        f.meta_dict = d["meta_dict"]
        f.record_key_bytes = base64.b64decode(d["record_key_bytes"]) \
            if d["record_key_bytes"] is not None else None
        f.file_data = base64.b64decode(d["file_data"]) \
            if d["file_data"] is not None else None
        return f

    @staticmethod
    def _record_to_dict(record):
        """Serialize a Record instance to a JSON-safe dictionary."""
        d = {
            "uid": record.uid,
            "title": record.title,
            "type": record.type,
            "raw_json": record.raw_json,
            "dict": record.dict,
            "password": record.password,
            "revision": record.revision,
            "is_editable": record.is_editable,
            "folder_uid": record.folder_uid,
            "inner_folder_uid": record.inner_folder_uid,
            "links": record.links,
            "files": [KeeperAnsible._file_to_dict(f) for f in record.files],
        }
        d["record_key_bytes"] = base64.b64encode(record.record_key_bytes).decode("ascii") \
            if record.record_key_bytes is not None else None
        return d

    @staticmethod
    def _record_from_dict(d):
        """Reconstruct a Record instance from a JSON-deserialized dictionary."""
        r = object.__new__(_Record)
        r.uid = d["uid"]
        r.title = d["title"]
        r.type = d["type"]
        r.raw_json = d["raw_json"]
        r.dict = d["dict"]
        r.password = d["password"]
        r.revision = d["revision"]
        r.is_editable = d["is_editable"]
        r.folder_uid = d["folder_uid"]
        r.inner_folder_uid = d["inner_folder_uid"]
        r.links = d["links"]
        r.record_key_bytes = base64.b64decode(d["record_key_bytes"]) \
            if d["record_key_bytes"] is not None else None
        r.files = [KeeperAnsible._file_from_dict(fd) for fd in d["files"]]
        return r

    def encrypt(self, data):
        secret_key = self.get_encryption_key()
        serializable = [KeeperAnsible._record_to_dict(r) for r in data]
        json_bytes = json.dumps(serializable).encode("utf-8")
        return Fernet(secret_key).encrypt(json_bytes)

    def decrypt(self, ciphertext):
        secret_key = self.get_encryption_key()
        try:
            plaintext = Fernet(secret_key).decrypt(ciphertext)
        except Exception as err:
            raise CacheUnusableError(
                "Unable to decrypt the record cache. Check keeper_record_cache_secret "
                "or regenerate the cache with keeper_cache_records."
            ) from err

        # Pickle protocol markers (e.g. 0x80) -- never call pickle.loads (CWE-502 / VM-1452).
        if plaintext.startswith(b"\x80"):
            raise CacheUnusableError(
                "Unable to deserialize the record cache. The cache may be from an older "
                "plugin version or is invalid. Regenerate the cache with keeper_cache_records."
            )

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as err:
            raise CacheUnusableError(
                "Unable to deserialize the record cache. The cache may be from an older "
                "plugin version or is invalid. Regenerate the cache with keeper_cache_records."
            ) from err

        if not isinstance(payload, list):
            raise CacheUnusableError(
                "Unable to deserialize the record cache. Expected a list of records. "
                "Regenerate the cache with keeper_cache_records."
            )

        try:
            return [KeeperAnsible._record_from_dict(d) for d in payload]
        except (KeyError, TypeError, ValueError) as err:
            raise CacheUnusableError(str(err)) from err

    @staticmethod
    def convert_records_into_dict(records):

        all_data = {
            "uid": {},
            "title": {}
        }

        if isinstance(records, list) is False:
            records = [records]

        for record in records:
            key_counter = {}
            record_data = {
                "keeper_title": record.title,
                "keeper_uid": record.uid
            }
            num = 0
            for field_type in ["fields", "custom"]:
                num += 1
                for field in record.dict.get(field_type, []):

                    # Use the label first for the key, else wall back to the field type. This is case-sensitive.
                    key = field.get("label", field.get("type"))

                    # Do not add plank types or labels
                    if key is None or key == "":
                        continue

                    key = key.replace(" ", "_")

                    if key in record_data:
                        if key not in key_counter:
                            key_counter[key] = 2
                        else:
                            key_counter[key] += 1
                        key = f"{key}_{key_counter[key]}"

                    value = field.get("value")
                    if value is not None:
                        if len(value) == 0:
                            value = None
                        elif len(value) == 1:
                            value = value[0]

                    record_data[key] = value
            all_data['uid'][record.uid] = record_data

            if record.title not in all_data['title']:
                all_data['title'][record.title] = []
            all_data['title'][record.title].append(record.uid)

        return all_data

    @staticmethod
    def _find_records(records, uids=None, titles=None):
        if titles is None:
            titles = []
        if isinstance(titles, list) is False:
            titles = [titles]

        if uids is None:
            uids = []
        if isinstance(uids, list) is False:
            uids = [uids]

        # These are used to make sure we got everything
        uid_map = {uid: True for uid in uids}
        title_map = {title: True for title in titles}

        found_records = {}
        for record in records:
            display.vvvvvv(f"found record uid: {record.uid}")
            for title in titles:
                if record.title == title:
                    found_records[record.uid] = record
                    title_map.pop(title, None)
            for uid in uids:
                if record.uid == uid:
                    found_records[record.uid] = record
                    uid_map.pop(uid, None)

        if len(uid_map) > 0:
            raise AnsibleError(f"The following record uid(s) could not be found: {list(uid_map.keys())}")
        if len(title_map) > 0:
            raise AnsibleError(f"The following record title(s) could not be found: {list(title_map.keys())}")

        return [found_records[x] for x in found_records]

    def get_records_from_vault(self, uids=None, titles=None, encrypt=False):

        display.vvvvvv("getting records from the Keeper Vault")

        if uids is None:
            uids = []
        if isinstance(uids, list) is False:
            uids = [uids]

        try:
            # If we are getting by titles, we need all the records. Even if getting UID, get all the records.
            if titles is not None:
                records = self.client.get_secrets()

            # If we are getting uid, we need only select amount.
            else:
                records = self.client.get_secrets(uids)
        except Exception as err:
            raise Exception("Cannot get record: {}".format(err))

        display.vvvvvv(f"got {len(records)} records")

        # Filter only the records we need. For UID only, it should be the same list.
        records = self._find_records(records, uids=uids, titles=titles)

        if encrypt is True:
            records = self.encrypt(records)

        return records

    def get_records_from_cache(self, cache, uids=None, titles=None):

        display.vvvvvv("getting records from cache")

        if titles is None:
            titles = []
        if isinstance(titles, list) is False:
            titles = [titles]

        if uids is None:
            uids = []
        if isinstance(uids, list) is False:
            uids = [uids]

        records = self.decrypt(cache)

        # Filter only the records we need. For UID only, it should be the same list.
        records = self._find_records(records, uids=uids, titles=titles)

        return records

    def get_records(self, uids=None, titles=None, cache=None, encrypt=False):

        if cache is not None:
            try:
                records = self.get_records_from_cache(cache, uids=uids, titles=titles)
            except CacheUnusableError:
                # Invalidate legacy/invalid cache and start from scratch via the vault.
                display.warning(
                    "Keeper record cache is unusable (legacy or invalid format) and was ignored. "
                    "Fetching records from the vault. Regenerate the cache with keeper_cache_records."
                )
                records = self.get_records_from_vault(uids=uids, titles=titles, encrypt=encrypt)
        else:
            records = self.get_records_from_vault(uids=uids, titles=titles, encrypt=encrypt)

        if records is None or len(records) == 0:
            raise ValueError("Could not find any records that meet the criteria.")
        return records

    def get_record(self, uids=None, titles=None, cache=None):

        records = self.get_records(cache=cache, uids=uids, titles=titles)
        if len(records) > 1 and titles is not None:
            raise AnsibleError("Found multiple records for the Title. To fix, make sure records "
                               "have a unique Title or use a UID.")

        return records[0]

    def create_record(self, new_record, shared_folder_uid, subfolder_uid=None):
        # KSM-816: use create_secret_with_options() instead of create_secret() so
        # that folder keys are fetched via the get_folders endpoint, which returns
        # all folders including empty ones. create_secret() uses get_secrets() which
        # only returns folder keys when the folder already contains records.
        #
        # Normalize a falsy subfolder_uid to None: the SDK sets payload.subFolderUid
        # unconditionally and serializes the whole payload, so an empty string from a
        # playbook would otherwise reach the server as subFolderUid: "".
        subfolder_uid = subfolder_uid or None
        try:
            record_uid = self.client.create_secret_with_options(
                CreateOptions(shared_folder_uid, subfolder_uid), new_record
            )
        except Exception as err:
            raise Exception("Cannot get create record: {}".format(err))

        return record_uid

    def create_folder(self, folder_name, shared_folder_uid, subfolder_uid=None):
        # shared_folder_uid must be the top-level shared folder UID. subfolder_uid, if given,
        # must be an existing folder nested (at any depth) under that shared folder; the new
        # folder is created inside it. If subfolder_uid is omitted, the new folder is created
        # directly inside the shared folder.
        #
        # Keeper allows more than one folder with the same name under the same parent, and the
        # create_folder API call itself has no create-if-missing behavior, so this method makes
        # the module idempotent by treating "a folder with this name already exists directly
        # under the target parent" as success instead of creating a duplicate.
        parent_uid = subfolder_uid if subfolder_uid else shared_folder_uid

        try:
            folders = self.client.get_folders()
        except Exception as err:
            raise Exception("Cannot get existing folders: {}".format(err))

        existing_folder = next(
            (f for f in folders if f.parent_uid == parent_uid and f.name == folder_name),
            None
        )
        if existing_folder is not None:
            return existing_folder.folder_uid, False

        try:
            folder_uid = self.client.create_folder(
                CreateOptions(shared_folder_uid, subfolder_uid), folder_name, folders=folders
            )
        except Exception as err:
            raise Exception("Cannot create folder: {}".format(err))

        return folder_uid, True

    def get_folders(self):
        """Get every folder the KSM application can see: its shared folders and all of their subfolders."""
        return self._read_folders()[0]

    def _read_folders(self):
        """
        Get the folder list, and the folders that the SDK could not read ({folder UID: error text}, see
        _UnreadableFolderLog). The SDK logger is set to WARNING for the call, so the SDK creates its warning, and
        then set back. The handler that the SDK adds has its own level, so the warning is not shown twice.
        """
        try:
            from keeper_secrets_manager_core.keeper_globals import logger_name
        except ImportError:
            logger_name = "ksm"
        sdk_logger = logging.getLogger(logger_name)
        unreadable = _UnreadableFolderLog()
        old_level, old_disabled = sdk_logger.level, sdk_logger.disabled
        sdk_logger.addHandler(unreadable)
        sdk_logger.disabled = False
        if sdk_logger.getEffectiveLevel() > logging.WARNING:
            sdk_logger.setLevel(logging.WARNING)
        try:
            folders = self.client.get_folders() or []
        except Exception as err:
            raise KeeperFolderError("Cannot get folders: {}".format(err))
        finally:
            sdk_logger.removeHandler(unreadable)
            sdk_logger.setLevel(old_level)
            sdk_logger.disabled = old_disabled
        return folders, unreadable.folders

    @staticmethod
    def _unreadable_note(unreadable):
        # For a "not found" message: the folder can be one that the SDK could not read.
        if not unreadable:
            return ""
        return (" keeper-secrets-manager-core could not read {} folder(s) ({}), so the folder can be one of them. "
                "A newer keeper-secrets-manager-core can read more folder formats.".format(
                    len(unreadable), ", ".join(sorted(unreadable))))

    @staticmethod
    def _check_uid(name, value, required=False):
        # An empty or padded UID usually comes from an empty template variable or a stray newline. Fail on it,
        # instead of letting it match no folder, which looks the same as a folder that does not exist.
        if value is None or str(value).strip() == "":
            if value is None and required is False:
                return None
            if required is True:
                raise KeeperFolderError("The {} is blank.".format(name))
            raise KeeperFolderError("The {} is set but blank. Set it to a folder UID, or remove it.".format(name))
        value = str(value)
        if value != value.strip():
            raise KeeperFolderError("The {} {!r} has leading or trailing whitespace.".format(name, value))
        return value

    @staticmethod
    def _folder_by_uid(folders, folder_uid):
        return next((f for f in folders if f.folder_uid == folder_uid), None)

    @staticmethod
    def _folder_children(folders, parent_uid):
        # A parent_uid of None means the top level: the shared folders, which have no parent.
        if parent_uid is None:
            return [f for f in folders if not f.parent_uid]
        return [f for f in folders if f.parent_uid == parent_uid]

    @staticmethod
    def _folder_ancestry(folders, folder):
        # The folder, its parent, and so on up to its shared folder. The walk stops at a parent that is not in
        # the list, or at a folder that it already visited, so a malformed server response cannot hang it.
        chain = []
        visited = set()
        current = folder
        while current is not None and current.folder_uid not in visited:
            chain.append(current)
            visited.add(current.folder_uid)
            if not current.parent_uid:
                break
            current = KeeperAnsible._folder_by_uid(folders, current.parent_uid)
        return chain

    @staticmethod
    def _quote(text):
        # For messages: the text in double quotes, with a newline, a tab, or a quote in it shown as an escape, so
        # that a stray character from a template or a file is visible.
        return json.dumps(str(text), ensure_ascii=False)

    @staticmethod
    def _folder_label(folders, folder):
        # For messages: the path of folder names from the shared folder, and the UID.
        path = "/".join(f.name for f in reversed(KeeperAnsible._folder_ancestry(folders, folder)))
        return "{} (UID {})".format(KeeperAnsible._quote(path), folder.folder_uid)

    @staticmethod
    def _folder_subtree(folders, folder_uid):
        # Every folder below folder_uid, depth first, with each parent before its children. A folder is added
        # only once, so a cycle in a malformed server response cannot hang the task.
        children = {}
        for f in folders:
            if f.parent_uid:
                children.setdefault(f.parent_uid, []).append(f)

        subtree = []
        visited = {folder_uid}
        stack = [iter(children.get(folder_uid, []))]
        while stack:
            child = next(stack[-1], None)
            if child is None:
                stack.pop()
            elif child.folder_uid not in visited:
                visited.add(child.folder_uid)
                subtree.append(child)
                stack.append(iter(children.get(child.folder_uid, [])))
        return subtree

    @staticmethod
    def _folder_to_dict(folder):
        return {
            "folder_uid": folder.folder_uid,
            "folder_name": folder.name,
            "parent_uid": folder.parent_uid or "",
        }

    @staticmethod
    def _folder_path_names(folder_path):
        # A string is split on "/". A list is used as it is, so a folder name that contains "/" can still be
        # found. An empty name is an error, not skipped: it usually comes from an empty template variable, and
        # to skip it would silently find a different folder.
        if KeeperAnsible._is_text(folder_path):
            names = str(folder_path).split("/")
        elif isinstance(folder_path, (list, tuple)):
            names = []
            for name in folder_path:
                if name is not None and not KeeperAnsible._is_text(name):
                    raise KeeperFolderError(
                        "Each folder_path item must be a folder name, but one item is {}. Put quotes around the "
                        "folder names.".format(KeeperAnsible._describe_value(name)))
                names.append("" if name is None else str(name))
        else:
            raise KeeperFolderError("The folder_path must be a string or a list of folder names.")

        if len(names) == 0 or "" in names:
            raise KeeperFolderError(
                "The folder_path {} has an empty folder name. Look for a leading, trailing, or double \"/\", "
                "or an empty list item.".format(json.dumps(names, ensure_ascii=False)))
        return names

    def get_folder(self, shared_folder_uid=None, subfolder_uid=None, folder_name=None, folder_path=None,
                   include_subfolders=False):
        """
        Find one folder and return a dictionary with its folder_uid, folder_name, parent_uid, and
        shared_folder_uid, and with subfolders if include_subfolders is True.

        The lookup starts at subfolder_uid if it is set, else at shared_folder_uid, else at the top level (the
        shared folders of the KSM application). If both UIDs are set, the subfolder must be inside the shared
        folder. Then folder_name finds a folder directly inside the start folder, or folder_path goes down one
        folder name at a time. With neither, the result is the start folder. Names must match exactly. If no
        folder matches, or more than one folder matches, this raises KeeperFolderError.
        """
        shared_folder_uid = self._check_uid("shared_folder_uid", shared_folder_uid)
        subfolder_uid = self._check_uid("subfolder_uid", subfolder_uid)

        if folder_name is not None and folder_path is not None:
            raise KeeperFolderError("The folder_name and folder_path are both set. Set only one of them.")
        if folder_name is not None:
            folder_name = str(folder_name)
            if folder_name == "":
                raise KeeperFolderError("The folder_name is set but blank. Set it to a folder name, or remove it.")
            names = [folder_name]
        elif folder_path is not None:
            names = self._folder_path_names(folder_path)
        else:
            names = []

        if shared_folder_uid is None and subfolder_uid is None and len(names) == 0:
            raise KeeperFolderError(
                "There is nothing to look up. Set shared_folder_uid, subfolder_uid, folder_name, or folder_path.")

        folders, unreadable = self._read_folders()

        start = None
        if shared_folder_uid is not None:
            start = self._folder_by_uid(folders, shared_folder_uid)
            if start is None:
                raise KeeperFolderError(
                    "The shared folder {} was not found, or it is not shared to this KSM application.{}".format(
                        shared_folder_uid, self._unreadable_note(unreadable)))
            if start.parent_uid:
                raise KeeperFolderError(
                    "The folder {} is a subfolder, not a shared folder. Set it as subfolder_uid instead.".format(
                        self._folder_label(folders, start)))

        if subfolder_uid is not None:
            subfolder = self._folder_by_uid(folders, subfolder_uid)
            if subfolder is None:
                raise KeeperFolderError(
                    "The subfolder {} was not found, or it is not shared to this KSM application.{}".format(
                        subfolder_uid, self._unreadable_note(unreadable)))
            if start is not None and self._folder_ancestry(folders, subfolder)[-1].folder_uid != start.folder_uid:
                raise KeeperFolderError("The subfolder {} is not inside the shared folder {}.".format(
                    self._folder_label(folders, subfolder), self._folder_label(folders, start)))
            start = subfolder

        folder = start
        for name in names:
            parent_uid = folder.folder_uid if folder is not None else None
            matches = [f for f in self._folder_children(folders, parent_uid) if f.name == name]
            if len(matches) == 1:
                folder = matches[0]
                continue

            if folder is None:
                where = "at the top level (the shared folders of this KSM application)"
                uid_option = "shared_folder_uid"
            else:
                where = "in the folder {}".format(self._folder_label(folders, folder))
                uid_option = "subfolder_uid"
            if len(matches) == 0:
                raise KeeperFolderError("No folder named {} was found {}.{}".format(
                    self._quote(name), where, self._unreadable_note(unreadable)))
            raise KeeperFolderError(
                "Found {} folders named {} {}: {}. Rename one of them in the vault. Or set {} to the UID of the "
                "folder that you want, and remove {} from folder_name or folder_path.".format(
                    len(matches), self._quote(name), where, ", ".join(f.folder_uid for f in matches), uid_option,
                    self._quote(name)))

        top = self._folder_ancestry(folders, folder)[-1]
        result = self._folder_to_dict(folder)
        result["shared_folder_uid"] = top.folder_uid if not top.parent_uid else None
        if include_subfolders:
            result["subfolders"] = [self._folder_to_dict(f) for f in self._folder_subtree(folders, folder.folder_uid)]
            if unreadable:
                display.warning(
                    "keeper-secrets-manager-core could not read {} folder(s) ({}). If they are below the folder {}, "
                    "they are not in subfolders.".format(len(unreadable), ", ".join(sorted(unreadable)),
                                                         self._folder_label(folders, folder)))
        return result

    def update_folder(self, folder_uid, new_folder_name, check_mode=False):
        """
        Rename a folder. Return a dictionary with changed, folder_uid, folder_name (the name after this call),
        and previous_folder_name.

        If the folder already has the new name, nothing is sent to the server. In check mode, nothing is sent
        to the server, and changed shows what a real run would do.
        """
        folder_uid = self._check_uid("folder_uid", folder_uid, required=True)
        if new_folder_name is None or str(new_folder_name).strip() == "":
            raise KeeperFolderError("The new_folder_name is blank.")
        new_folder_name = str(new_folder_name)
        # A space or a newline at the start or the end usually comes from a template or from YAML, not from the
        # author: a block scalar (|) keeps the newline at its end. A lookup of the name would then not find the
        # folder, so this fails like a padded UID does.
        if new_folder_name != new_folder_name.strip():
            raise KeeperFolderError(
                "The new_folder_name {!r} has leading or trailing whitespace. Remove it. In YAML, a block scalar "
                "(| or >) keeps the newline at its end.".format(new_folder_name))

        folders, unreadable = self._read_folders()
        folder = self._folder_by_uid(folders, folder_uid)
        if folder is None:
            raise KeeperFolderError(
                "The folder {} was not found, or it is not shared to this KSM application.{}".format(
                    folder_uid, self._unreadable_note(unreadable)))

        result = {
            "changed": folder.name != new_folder_name,
            "folder_uid": folder_uid,
            "folder_name": new_folder_name,
            "previous_folder_name": folder.name,
        }
        if result["changed"] is False:
            display.vvv("Folder {} is already named {}. Nothing to rename.".format(
                folder_uid, self._quote(new_folder_name)))
            return result

        # Keeper allows two folders with the same name in one parent, so this is not an error. But a later
        # lookup of the name with keeper_get_folder fails, because the name is no longer unique.
        same_name = [f for f in self._folder_children(folders, folder.parent_uid or None)
                     if f.folder_uid != folder_uid and f.name == new_folder_name]
        if len(same_name) > 0:
            display.warning(
                "The parent of the folder {} already has a folder named {} ({}). After the rename, a lookup of "
                "this name fails because the name is not unique.".format(
                    self._folder_label(folders, folder), self._quote(new_folder_name),
                    ", ".join(f.folder_uid for f in same_name)))

        if check_mode:
            return result

        try:
            self.client.update_folder(folder_uid, new_folder_name, folders=folders)
        except Exception as err:
            raise KeeperFolderError("Cannot rename the folder {}: {}".format(self._folder_label(folders, folder), err))

        return result

    @staticmethod
    def _folder_delete_statuses(response):
        # The per-folder results from SecretsManager.delete_folder(), as a list of dictionaries. SDK 17.3.0
        # returns the server's "folders" list, or {} if the server sent none. Later versions return a list.
        if isinstance(response, dict):
            response = response.get("folders", [])
        if not isinstance(response, list):
            return []
        return [status for status in response if isinstance(status, dict)]

    def delete_folder(self, folder_uid, force=False, check_mode=False):
        """
        Delete a folder. Return a dictionary with changed, folder_uid, and folder_name.

        A folder that does not exist, or that is not shared to the KSM application, is not an error: changed
        is False, the same as when an earlier run already deleted the folder. A folder that contains records or
        subfolders is an error, unless force is True. Only the value True enables force, so a string such as
        "false" can never delete a folder's contents. In check mode, nothing is sent to the server.
        """
        folder_uid = self._check_uid("folder_uid", folder_uid, required=True)
        force = force is True

        folders, unreadable = self._read_folders()
        folder = self._folder_by_uid(folders, folder_uid)
        if folder is None:
            # A folder that the SDK skipped exists. Reporting it as not found would say that nothing is left to
            # delete, while the folder is still in the vault.
            if folder_uid in unreadable:
                raise KeeperFolderError(
                    "The folder {} exists, but keeper-secrets-manager-core could not read it ({}). Nothing was "
                    "deleted. A newer keeper-secrets-manager-core can read more folder formats.".format(
                        folder_uid, unreadable[folder_uid]))
            return {
                "changed": False,
                "folder_uid": folder_uid,
                "folder_name": None,
                "msg": "The folder {} was not found, or it is not shared to this KSM application. Nothing was "
                       "deleted.".format(folder_uid),
            }

        label = self._folder_label(folders, folder)

        if force is False:
            subfolders = self._folder_children(folders, folder_uid)
            try:
                records = self.client.get_secrets() or []
            except Exception as err:
                raise KeeperFolderError("Cannot get records to check if the folder {} is empty: {}".format(label, err))

            # A record in a subfolder has the subfolder UID in inner_folder_uid. A record at the top of a shared
            # folder has only folder_uid.
            records = [r for r in records if r.inner_folder_uid == folder_uid or
                       (not r.inner_folder_uid and r.folder_uid == folder_uid)]
            if unreadable:
                display.warning(
                    "keeper-secrets-manager-core could not read {} folder(s) ({}), so the module cannot count them. If "
                    "one of them is inside the folder {}, only the Keeper server check stops the delete.".format(
                        len(unreadable), ", ".join(sorted(unreadable)), label))
            if len(subfolders) > 0 or len(records) > 0:
                raise KeeperFolderError(
                    "The folder {} is not empty. It contains {} record(s) and {} subfolder(s). Set force_deletion to "
                    "true to delete the folder and everything in it.".format(label, len(records), len(subfolders)))

        result = {"changed": True, "folder_uid": folder_uid, "folder_name": folder.name}
        if check_mode:
            return result

        try:
            response = self.client.delete_folder([folder_uid], force_deletion=force)
        except Exception as err:
            raise KeeperFolderError("Cannot delete the folder {}: {}".format(label, err))

        # The server does not raise an error when it refuses to delete a folder. It returns a responseCode for
        # each folder, so a refused delete must be found here, or the task would report a delete that did not
        # happen.
        status = next((s for s in self._folder_delete_statuses(response) if s.get("folderUid") == folder_uid), None)
        if status is None:
            try:
                folders_after = self.get_folders()
            except KeeperFolderError as err:
                raise KeeperFolderError(
                    "The Keeper server sent no result for the delete of the folder {}, and the check of the folder "
                    "list after it failed, so the folder can still exist. {}".format(label, err))
            if self._folder_by_uid(folders_after, folder_uid) is not None:
                raise KeeperFolderError(
                    "The Keeper server did not confirm the delete of the folder {}, and the folder still "
                    "exists.".format(label))
        elif status.get("responseCode") != "ok":
            detail = status.get("responseCode") or "no response code"
            if status.get("errorMessage"):
                detail = "{}: {}".format(detail, status.get("errorMessage"))
            raise KeeperFolderError("The Keeper server did not delete the folder {}. It returned {}.".format(
                label, detail))

        return result

    def remove_record(self, uids=None, titles=None, cache=None):

        records = self.get_records(cache=cache, uids=uids, titles=titles)
        if len(records) > 1 and titles is not None:
            raise AnsibleError("Found multiple records for the Title. To fix, make sure records "
                               "have a unique Title or use a UID.")

        display.vvvvvv(f"removing record UID {records[0].uid}")

        self.client.delete_secret([records[0].uid])

    @staticmethod
    def _gather_secrets(obj):
        """
        Walk the secret structure and get values.
        These should just be str, list, and dict.
        Warn if the SDK returns something different.
        """
        result = []
        if type(obj) is str:
            result.append(obj)
        elif type(obj) is list:
            for item in obj:
                result += KeeperAnsible._gather_secrets(item)
        elif type(obj) is dict:
            for k, v in obj.items():
                result += KeeperAnsible._gather_secrets(v)
        else:
            display.warning("Result item is not string, list, or dictionary, can't get secret values: "
                            + str(type(obj)))
        return result

    def stash_secret_value(self, value):
        """
        Parse the result of the secret retrieval and add values to a list of secret values.
        """
        for secret_value in self._gather_secrets(value):
            if secret_value not in self.secret_values:
                self.secret_values.append(secret_value)

    def get_value_via_notation(self, notation):
        value = self.client.get_notation(notation)
        self.stash_secret_value(value)
        return value

    def get_value(self, field_type, key, uid=None, title=None, allow_array=False, array_index=None, value_key=None,
                  cache=None):

        record = self.get_record(uids=uid, titles=title, cache=cache)

        # Make sure the boolean is a boolean.
        allow_array = bool(strtobool(str(allow_array)))

        values = None
        if field_type == KeeperFieldType.FIELD:
            values = record.field(key)
        elif field_type == KeeperFieldType.CUSTOM_FIELD:
            values = record.custom_field(key)
        elif field_type == KeeperFieldType.FILE:
            file = record.find_file_by_title(key)
            if file is not None:
                values = [file.get_file_data()]
                display.vvvvvv(f"found the file: {key}")
            else:
                display.vvvvvv(f"cannot find the file: {key}")
        elif field_type == KeeperFieldType.NOTES:
            notes_value = record.dict.get('notes')
            if notes_value is not None:
                values = [notes_value]
                display.vvvvvv(f"found notes field")
            else:
                display.vvvvvv(f"notes field is empty or not present")
        else:
            raise AnsibleError("Cannot get_value. The field type ENUM of {} is invalid.".format(field_type))

        if values is None:
            raise AnsibleError("Cannot find key {} in the record for uid {} and field_type {}".format(key, uid,
                                                                                                      field_type.name))

        if len(values) == 0:
            display.debug("The value for uid {}, field_type {}, key {} was None or was an empty list.".format(
                uid, field_type.name, key))
            return None

        self.stash_secret_value(values)

        # If we want the entire array, then return what we got from the field.
        if allow_array is True:
            return values

        if array_index is None:
            array_index = 0

        # If we got here, we know at least one item exists in the array.
        try:
            value = values[array_index]
        except IndexError:
            raise AnsibleError(f"An array index of {array_index} does not exists in the field value.")
        if value_key is not None:
            if value_key not in value:
                if array_index > 0:
                    display.warning("The value_key attribute was used with array_index. Make sure the value key exists "
                                    "in that item's object")
                raise AnsibleError(f"The value key {value_key} does not exists in the field value.")
            value = value[value_key]

        return value

    def get_dict(self, uid=None, title=None, cache=None, allow=None):

        record = self.get_record(uids=uid, titles=title, cache=cache)

        record_dict = {}
        for field_section in ["fields", "custom"]:
            for field in record.dict.get(field_section, []):
                label = field.get("label")
                type = field.get("type")
                value = field.get("value", [])
                key = label if label is not None else type

                if key is None or key == "":
                    display.vvvvv("record contains a field without a label or type.")
                    continue

                # Scrub the label to make it a clean key.
                # Only allow alphanumerics, remove runs of _, remove _ at the start and end of the key.
                key = re.sub('[^0-9a-zA-Z]+', '_', key)
                key = re.sub('_+', '_', key)
                key = re.sub('^_+', '', key)
                key = re.sub('_+$', '', key)

                if key == "":
                    display.vvvvv("record contains a field that has no alphanumeric characters. cannot use this field.")
                    continue

                if key in record_dict:
                    count = len([x for x in record_dict if x.startswith(key)])
                    key = key + "_" + str(count)

                if allow is not None and key not in allow:
                    continue

                record_dict[key] = value
                self.stash_secret_value(value)

        return record_dict

    def set_value(self, field_type, key, value, uid=None, title=None, cache=None):

        record = self.get_record(uids=uid, titles=title, cache=cache)

        if field_type == KeeperFieldType.FIELD:
            record.field(key, value)
        elif field_type == KeeperFieldType.CUSTOM_FIELD:
            record.custom_field(key, value)
        elif field_type == KeeperFieldType.FILE:
            raise AnsibleError("Cannot save a file from the ansible playbook/role to Keeper.")
        elif field_type == KeeperFieldType.NOTES:
            record.dict["notes"] = value
            record._update()
        else:
            raise AnsibleError("Cannot set_value. The field type ENUM of {} is invalid.".format(field_type))

        self.client.save(record)

    @staticmethod
    def get_field_type_enum_and_key(args):

        """
        Get the field type enum and field key in the Ansible args for a task.

        For a task that only allowed one of the allowed fields, this method will find the type of field and
        the key/label for that field.

        If multiple fields types are specified, an error will be thrown.
        If no fields are found, an error will be thrown.

        The method will return the KeeperFieldType enum for the field type and the name of the field in Keeper that
        the task requires.
        """

        field_type = []
        field_key = None
        for key in KeeperAnsible.ALLOWED_FIELDS:
            if args.get(key) is not None:
                field_type.append(key)
                # Notes is a singleton field (no lookup needed), others use the value as a lookup key
                field_key = None if key == "notes" else args.get(key)

        if len(field_type) == 0:
            raise AnsibleError("Either field, custom_field, file, or notes needs to set to a non-blank value for keeper_copy.")
        if len(field_type) > 1:
            raise AnsibleError("Found multiple field types. Only one of the following key can be set: field, "
                               "custom_field, file, or notes.")

        return KeeperFieldType.get_enum(field_type[0]), field_key

    def add_secret_values_to_results(self, results):
        """
        If the 'redact' stdout callback is being used, add the secrets to the result dictionary.
        The redacted stdout callback will remove it from the results.
        It will use value to remove values from stdout.
        """

        # If we are using the redacted stdout callback, add the secrets we retrieve to the special key.
        # The redacted stdout callback will make sure the value is not in the stdout.
        if self.has_redact is True:
            results["_secrets"] = self.secret_values
        return results

    @staticmethod
    def password_complexity_translation(**kwargs):
        """
        Generate a password complexity dictionary.

        Password complexity differs from place to place.

        This is in more tune with the Vault UI since most services just want a specific set of characters, but not
        a quantity.
        And some characters are illegal for specific services.
        Neither the SDK and Vault UI address this.
        So this is the third standard.

        Kwargs

        * length - Length of the password
        * allow_lowercase - Allow lowercase letters. Default is True.
        * allow_uppercase - Allow uppercase letters. Default is True.
        * allow_digits - Allow digits. Default is True.
        * allow_symbols - Allow symbols. Default is True
        * filter_characters - An array of characters not to use. Some services don't like some characters.

        The length is divided by the allowed characters.
        So with a length of 64, each would get 16 of all characters.
        If the length cannot be unevenly divided, additional will be added to the first allowed character in the above
        list.

        """

        # This maps nicer human-readable keys to the ones used the records' complexity.
        kwargs_map = [
            {"param": "allow_lowercase", "key": "lowercase"},
            {"param": "allow_uppercase", "key": "caps"},
            {"param": "allow_digits", "key": "digits"},
            {"param": "allow_symbols", "key": "special"},
        ]

        length = kwargs.get("length", 64)

        count = 0
        for key in [x["param"] for x in kwargs_map]:
            # not False, because None == True
            count += 1 if kwargs.get(key) is not False else 0
        if count == 0:
            raise AnsibleError()
        per_amount = int(length / count)

        filter_characters = kwargs.get("filter_characters")
        if filter_characters is not None:
            if isinstance(filter_characters, list) is False:
                filter_characters = str(filter_characters)

        complexity = {
            "length": length,

            # This is not part of the standard, however, it's important because some service will not accept certain
            # characters.
            "filter_characters": filter_characters
        }
        for item in kwargs_map:
            if kwargs.get(item.get("param")) is not False:
                complexity[item.get("key")] = per_amount
                length -= per_amount
            else:
                complexity[item.get("key")] = 0
        if length > 0:
            for item in kwargs_map:
                if kwargs.get(item.get("param")) is not False:
                    complexity[item.get("key")] += length
                    break
        return complexity

    @staticmethod
    def replacement_char(**kwargs):

        """
        Get a replacement character that doesn't match the bad character.
        """

        lowercase = kwargs.get("lowercase", 0)
        caps = kwargs.get("caps", 0)
        digits = kwargs.get("digits", 0)
        special = kwargs.get("special", 0)

        new_char = None
        all_true = (lowercase + caps + digits + special) == 0

        attempt = 0
        while True:
            # If allow everything, then get a lowercase letter
            if all_true is True:
                new_char = "abcdefghijklmnopqrstuvwxyz"[random.randint(0, 25)]

            # Else we need to find the first allowed character set.
            else:
                pick_one = random.randint(0, 3)
                if pick_one == 0 and lowercase > 0:
                    new_char = "abcdefghijklmnopqrstuvwxyz"[random.randint(0, 25)]
                if pick_one == 1 and caps > 0:
                    new_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random.randint(0, 25)]
                if pick_one == 2 and digits > 0:
                    new_char = "0123456789"[random.randint(0, 9)]
                if pick_one == 3 and special > 0:
                    new_char = "!@#$%^&*()"[random.randint(0, 9)]

                if new_char is None:
                    continue

            # If our new character is not in the list of bad characters, break out of the while
            if new_char not in kwargs.get("filter_characters"):
                break

            # Ok, some user might go overboard and filter out every letter, digit, and symbol
            # and cause an infinite loop.
            # If we can't find a good character after 25 attempts, error out.
            attempt += 1
            if attempt > 25:
                raise ValueError("Cannot filter character from password. The password complexity is too complex.")

        return new_char

    @staticmethod
    def filter_password(password, **kwargs):

        # Make sure the bad_char is a str, and not something like an int
        for bad_char in kwargs.get("filter_characters"):
            while str(bad_char) in password:
                password = password.replace(str(bad_char), KeeperAnsible.replacement_char(**kwargs), 1)
        return password

    @staticmethod
    def generate_password(**kwargs):

        # The SDK generate_password doesn't know what the filter_characters is, remove it for now.
        filter_characters = kwargs.pop("filter_characters", None)

        # The SDK uses these a params, record complexity uses the ones on the right.
        # Translate them.
        kwargs["uppercase"] = kwargs.pop("caps", None)
        kwargs["special_characters"] = kwargs.pop("special", None)

        # Generate the password
        password = sdk_generate_password(**kwargs)

        # If we have a character filter, remove bad characters from the password
        if filter_characters is not None:
            if isinstance(filter_characters, str) is True:
                temp = []
                temp.extend(filter_characters)
                filter_characters = temp

            # Add back the filter_characters in the right data type
            kwargs["filter_characters"] = filter_characters

            password = KeeperAnsible.filter_password(password, **kwargs)

        return password

    def cleanup(self):

        status = {}

        # If we are using the cache, remove the cache file.
        if self.using_cache is True:
            KSMCache.remove_cache_file()
            status["removed_ksm_cache"] = True

        return status