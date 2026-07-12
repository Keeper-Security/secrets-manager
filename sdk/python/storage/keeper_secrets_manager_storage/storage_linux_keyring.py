import hashlib
import json
import logging
import os
import shutil
import subprocess

from keeper_secrets_manager_core.helpers import is_json
from keeper_secrets_manager_core import exceptions
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.utils import is_base64, url_safe_str_to_bytes


class KeyringUtilityStorage(KeyValueStorage):
    """Linux Keyring Utility Storage extends the key value storage interface.
    It delegates storage and retrieval to the Linux Keyring Utility.
    The utility is an executable with a known SHA256 hash.
    """

    SHA256SUMS = [
        # lkru-v0.2.0_linux_amd64
        "0B08A4662575CFAE30A89B0339D5A204D0C7F9DB6B37A0D8B394AC5F06DEBF31",
    ]

    logger = logging.getLogger(logger_name)

    @classmethod
    def __fatal(cls, message: str, error: Exception = None):
        message = f"{cls.__name__}: {message}"
        cls.logger.error(message, error)
        raise exceptions.KeeperError(message, error)

    def __init__(
        self,
        secret_name: str,
        keyring_application_name: str = None,
        keyring_collection_name: str = None,
        check_keyring_utility_hash: bool = True,
        keyring_utility: str = "lkru",
        keyring_utility_path: str = None,
    ):
        if not secret_name:
            self.__fatal("Linux Keyring Utility Storage requires a secret name")
        self.secret_name = secret_name
        self.logger.debug(
            f"Linux Keyring Utility Storage using secret name: {self.secret_name}"
        )

        if keyring_utility_path:
            if p := os.path.abspath(keyring_utility_path).strip():
                if os.path.exists(p):
                    self.keyring_utility_path = p
                    self.logger.debug(
                        f"Linux Keyring Utility Storage using utility at: {self.keyring_utility_path}"
                    )
            else:
                self.__fatal(
                    f"Invalid Linux Keyring Utility path: {keyring_utility_path}"
                )
        elif p := os.getenv("KSM_CONFIG_KEYRING_UTILITY_PATH"):
            if os.path.exists(p):
                self.logger.debug(
                    f"Using Linux Keyring Utility path from KSM_CONFIG_KEYRING_UTILITY_PATH: {p}"
                )
                self.keyring_utility_path = p
            else:
                self.__fatal(
                    f"Invalid Linux Keyring Utility path in KSM_CONFIG_KEYRING_UTILITY_PATH: {p}"
                )
        elif p := shutil.which(keyring_utility):
            self.keyring_utility_path = p
            self.logger.debug(
                f"Linux Keyring Utility Storage using utility at: {self.keyring_utility_path}"
            )
        else:
            self.__fatal("No Linux Keyring Utility")

        self.check_keyring_utility_hash = check_keyring_utility_hash
        self.logger.debug(
            f"Linux Keyring Utility Storage will{' *not*' if check_keyring_utility_hash else ''} check hash"
        )

        self.keyring_application_name = keyring_application_name
        if self.keyring_application_name:
            self.logger.debug(
                f"Linux Keyring Utility Storage using application name '{self.keyring_application_name}'"
            )

        self.keyring_collection_name = keyring_collection_name
        if self.keyring_collection_name:
            self.logger.debug(
                f"Linux Keyring Utility Storage using collection '{self.keyring_collection_name}'"
            )

        self.config = {}
        self.config_hash = None
        self.__load_config()

    def __run_keyring_utility(self, args: list[str]) -> str:
        if self.check_keyring_utility_hash:
            with open(self.keyring_utility_path, "rb") as file:
                if (
                    hashlib.file_digest(file, "sha256").hexdigest().upper()
                    not in self.SHA256SUMS
                ):
                    self.__fatal(
                        f"Linux Keyring Utility '{self.keyring_utility_path}' is not a known release"
                    )
        try:
            match args[0]:
                case "get" | "set":
                    args.append("-b")
            if self.keyring_application_name:
                args.insert(1, self)
                args.insert(1, "-a")
            if self.keyring_collection_name:
                args.insert(1, self)
                args.insert(1, "-c")
            args.insert(0, self.keyring_utility_path)
            self.logger.debug(f"Running Linux Keyring Utility as: {args}")
            return (
                subprocess.run(
                    args,
                    capture_output=True,
                    check=True,  # so it raises an exception if return code is not 0
                    executable=self.keyring_utility_path,
                )
                .stdout.decode()
                .strip()
            )
        except subprocess.CalledProcessError as e:
            message = f"Linux Keyring Utility exited with {e.returncode}"
            if e.stderr:
                message += f" with error output '{e.stderr.decode().strip()}'"
            self.__fatal(message, e)

    # low level hepler methods to do actual read/write
    def __load_config(self):
        try:
            contents = self.__run_keyring_utility(["get", self.secret_name])
            if is_base64(contents):
                contents = url_safe_str_to_bytes(contents)
            if is_json(contents):
                self.config = json.loads(contents)
                self.config_hash = hashlib.md5(
                    json.dumps(self.config, indent=4, sort_keys=True).encode()
                ).hexdigest()
            else:
                self.__fatal(
                    f"Unable to parse Linux Keyring Utility 'get' output as JSON: '{contents}'"
                )

        except Exception as e:
            self.logger.error(f"Failed to load config JSON from Keyring utlity: {str(e)}")

    def __save_config(self, updated_config: dict = None, force: bool = False):
        if updated_config:
            config = json.dumps(updated_config, indent=4, sort_keys=True)
            hash = hashlib.md5(config.encode()).hexdigest()
            if hash != self.config_hash or force:
                try:
                    self.__run_keyring_utility(["set", self.secret_name, config])
                except Exception as e:
                    self.logger.error(
                        f"Failed to save config JSON to Linux Keyring Utility: {str(e)}"
                    )
                self.config_hash = hash
                self.config = dict(updated_config)
            else:
                self.logger.warning("Skipped config JSON save. No changes detected.")
                return

    # Interface methods implementation
    def read_storage(self):
        if not self.config:
            self.__load_config()
        return dict(self.config)

    def save_storage(self, updated_config):
        self.__save_config(updated_config)

    def get(self, key: ConfigKeys):
        config = self.read_storage()
        return config.get(key.value)

    def set(self, key: ConfigKeys, value):
        config = self.read_storage()
        config[key.value] = value
        self.save_storage(config)
        return config

    def delete(self, key: ConfigKeys):
        config = self.read_storage()

        kv = key.value
        if kv in config:
            del config[kv]
            self.logger.debug(f"Removed key {kv}")
        else:
            self.logger.debug(f"No key {kv} was found in config")

        self.save_storage(config)
        return config

    def delete_all(self):
        self.read_storage()
        self.config.clear()
        self.save_storage(self.config)
        return dict(self.config)

    def contains(self, key: ConfigKeys):
        config = self.read_storage()
        return key.value in config

    def is_empty(self):
        config = self.read_storage()
        return not config
