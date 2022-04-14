#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
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

    def __init__(self, task_vars, force_in_memory=False):

        """ Build the config used by the Keeper Python SDK

        The configuration is mainly read from a JSON file.
        """

        if KSM_SDK_ERR is not None:
            self.fail_json(msg=missing_required_lib('keeper-secrets-manager-core'), exception=KSM_SDK_ERR)

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

            # By default we don't want to skip verify the certs.
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

                display.vvv("Keeper Secrets Manager is using cache. Cache directory is {}.".format(
                    os.environ.get(KeeperAnsible.ENV_CACHE_DIR)
                    if os.environ.get(KeeperAnsible.ENV_CACHE_DIR) is not None else "current working directory"))

                self.using_cache = True
            else:
                display.vvv("Keeper Secrets Manager is not using a cache.")

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

                # Sometime we don't want a JSON file, ever. Force the config to be in memory.
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

    def get_record(self, uid):

        try:
            records = self.client.get_secrets([uid])
            if records is None or len(records) == 0:
                raise ValueError("The uid {} was not found in the Keeper Secrets Manager app.".format(uid))
        except Exception as err:
            raise Exception("Cannot get record: {}".format(err))

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

    def get_value(self, uid, field_type, key, allow_array=False):

        record = self.get_record(uid)

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

        # Else return the first item.
        return values[0]

    def set_value(self, uid, field_type, key, value):

        record = self.get_record(uid)

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
        """ If the redact stdout callback is being used, add the secrets to the results dictionary. The redact
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
        a quantity. And some character are illegal for specific services. Neither the SDK and Vault UI address this.
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
