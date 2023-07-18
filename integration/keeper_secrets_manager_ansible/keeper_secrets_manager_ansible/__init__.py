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
from distutils.util import strtobool
import os
import sys
import re
import json
import random
from re import sub
from enum import Enum
import traceback
import pickle
import io
import base64
import socket

# Check if the KSM SDK core has been installed
KSM_SDK_ERR = None
try:
    import keeper_secrets_manager_core
except ImportError:
    KSM_SDK_ERR = traceback.format_exc()
else:
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.core import KSMCache
    from keeper_secrets_manager_core.storage import FileKeyValueStorage, InMemoryKeyValueStorage
    from keeper_secrets_manager_core.utils import generate_password as sdk_generate_password

    # If keeper_secrets_manager_core is installed, then these will be installed. They are deps.
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


display = Display()


class KeeperFieldType(Enum):
    FIELD = "field"
    CUSTOM_FIELD = "custom_field"
    FILE = "file"

    @staticmethod
    def get_enum(value):
        for e in KeeperFieldType:
            if e.value == value:
                return e
        return None


class KeeperAnsible:
    """ A class containing common method used by the Ansible plugin and also talked to Keeper Python SDK
    """

    KEY_PREFIX = "keeper"
    KEY_CONFIG_FILE_SUFFIX = "config_file"
    KEY_CONFIG_BASE64 = "config"
    ALLOWED_FIELDS = ["field", "custom_field", "file"]
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

    def __init__(self, task_vars, action_module=None, task_attributes=None, force_in_memory=False):

        """ Build the config used by the Keeper Python SDK

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
            text = sub(r"([_\-])+", " ", text).title().replace(" ", "")
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
            self.config_file = task_vars.get(keeper_config_file_key)
            if self.config_file is None:
                self.config_file = FileKeyValueStorage.default_config_file_location

            # Should we be using the cache?
            use_cache_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_USE_CACHE)
            custom_post_function = None
            if bool(strtobool(str(task_vars.get(use_cache_key, "False")))) is True:
                custom_post_function = KSMCache.caching_post_function

                # We are using the cache, what directory should the cache file be stored in.
                cache_dir_key = KeeperAnsible.keeper_key(KeeperAnsible.KEY_CACHE_DIR)
                if task_vars.get(cache_dir_key) is not None and os.environ.get(KeeperAnsible.ENV_CACHE_DIR) is None:
                    os.environ[KeeperAnsible.ENV_CACHE_DIR] = task_vars.get(cache_dir_key)

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
                # not to leave config files laying around.
                in_memory_storage = True

                # If be have parameter with a Base64 config, use it for the config_option and force
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

                    # Token is the odd ball. we need it to be client key in the SDK config. SDK will remove it
                    # when it is done.
                    token_key = KeeperAnsible.keeper_key(KeeperAnsible.TOKEN_KEY)
                    if token_key in task_vars:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = task_vars[token_key]

                    # If the secret client key is in the environment, override the Ansible var.
                    if os.environ.get(KeeperAnsible.TOKEN_ENV) is not None:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = os.environ.get(KeeperAnsible.TOKEN_ENV)
                    elif token_key in task_vars:
                        config_option[KeeperAnsible.CONFIG_CLIENT_KEY] = task_vars[token_key]

                    # If no variables were passed in throw an error.
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

                    # Write the variables we have to a JSON file. If we are in here config_option is a dictionary,
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

    def encrypt(self, data):

        secret_key = self.get_encryption_key()
        record_fh = io.BytesIO()
        pickle.dump(data, record_fh)
        return Fernet(secret_key).encrypt(record_fh.getvalue())

    def decrypt(self, ciphertext):
        secret_key = self.get_encryption_key()
        return pickle.loads(Fernet(secret_key).decrypt(ciphertext))

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
            raise ValueError(f"The following record uid(s) could not be found: {list(uid_map.keys())}")
        if len(title_map) > 0:
            raise ValueError(f"The following record title(s) could not be found: {list(title_map.keys())}")

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

            # If we are getting uid we need only select amount.
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
            records = self.get_records_from_cache(cache, uids=uids, titles=titles)
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

    def create_record(self, new_record, shared_folder_uid):
        try:
            record_uid = self.client.create_secret(shared_folder_uid, new_record)
        except Exception as err:
            raise Exception("Cannot get create record: {}".format(err))

        return record_uid

    @staticmethod
    def _gather_secrets(obj):
        """ Walk the secret structure and get values. These should just be str, list, and dict. Warn if the SDK
        return something different.
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
        """ Parse the result of the secret retrieval and add values to list of secret values.
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

        # If we want the entire array, then just return what we got from the field.
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

    def set_value(self, field_type, key, value, uid=None, title=None, cache=None):

        record = self.get_record(uids=uid, titles=title, cache=cache)

        if field_type == KeeperFieldType.FIELD:
            record.field(key, value)
        elif field_type == KeeperFieldType.CUSTOM_FIELD:
            record.custom_field(key, value)
        elif field_type == KeeperFieldType.FILE:
            raise AnsibleError("Cannot save a file from the ansible playbook/role to Keeper.")
        else:
            raise AnsibleError("Cannot set_value. The field type ENUM of {} is invalid.".format(field_type))

        self.client.save(record)

    @staticmethod
    def get_field_type_enum_and_key(args):

        """ Get the field type enum and field key in the Ansible args for a task.

        For a task that, only allowed one of the allowed field, this method will find the type of field and
        the key/label for that field.

        If multiple fields types are specified, an error will be thrown. If no fields are found, an error will be
        thrown.

        The method will return the KeeperFieldType enum for the field type and the name of the field in Keeper that
        the task requires.
        """

        field_type = []
        field_key = None
        for key in KeeperAnsible.ALLOWED_FIELDS:
            if args.get(key) is not None:
                field_type.append(key)
                field_key = args.get(key)

        if len(field_type) == 0:
            raise AnsibleError("Either field, custom_field or file needs to set to a non-blank value for keeper_copy.")
        if len(field_type) > 1:
            raise AnsibleError("Found multiple field types. Only one of the following key can be set: field, "
                               "custom_field or file.")

        return KeeperFieldType.get_enum(field_type[0]), field_key

    def add_secret_values_to_results(self, results):
        """ If the 'redact' stdout callback is being used, add the secrets to the results dictionary. The redact
        stdout callback will remove it from the results. It will use value to remove values from stdout.
        """

        # If we are using the redact stdout callback, add the secrets we retrieve to the special key. The redact
        # stdout callback will make sure the value is not in the stdout.
        if self.has_redact is True:
            results["_secrets"] = self.secret_values
        return results

    @staticmethod
    def password_complexity_translation(**kwargs):
        """
        Generate a password complexity dictionary

        Password complexity differ from place to place :(

        This is in more tune with the Vault UI since most service just want a specific set of characters, but not
        a quantity. And some characters are illegal for specific services. Neither the SDK and Vault UI address this.
        So this is the third standard.

        kwargs

        * length - Length of the password
        * allow_lowercase - Allow lowercase letters. Default is True.
        * allow_uppercase - Allow uppercase letters. Default is True.
        * allow_digits - Allow digits. Default is True.
        * allow_symbols - Allow symbols. Default is True
        * filter_characters - An array of characters not to use. Some servies don't like some characters.

        The length is divided by the allowed characters. So with a length of 64, each would get 16 of each characters.
        If the length cannot be unevenly divided, additional will be added to the first allowed character in the above
        list.

        """

        # This maps nicer human readable keys to the ones used the records' complexity.
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

            # This is not part of the standard, however it's important because some service will not accept certain
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
            # If allow everything, then just get a lowercase letter
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

            # Ok, some user might go crazy and filter out every letter, digit, and symbol and cause an invite loop.
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

        # The SDK uses these a params, record complexity use the ones on the right. Translate them.
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
