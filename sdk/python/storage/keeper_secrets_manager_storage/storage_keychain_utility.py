import base64
import hashlib
import json
import logging
import os
import platform
import subprocess
from enum import Enum

from keeper_secrets_manager_core.helpers import is_json
from keeper_secrets_manager_core import exceptions
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.utils import is_base64, url_safe_str_to_bytes

logger = logging.getLogger(logger_name)


class KeychainUtilityStorage(KeyValueStorage):
    """Keychain Utility Storage extends the key value storage interface.
    It delegates storage and retrieval to the Keychain Utility.
    The utility is an executable with a known SHA256 hash.
    """

    class KeychainUtility:
        SHA256SUMS = {
            "Linux": {
                "5C9848AAB7ABCC1842C941D6EB42A55E0C2AD140E5D8F94CA798DF1B336ECFDF": "lku-v0.1.1_linux_amd64",
            },
            "Windows": {
                "8EAEB30AE5DEC8F1C3D957C3BC0433D8F18FCC03E5C761A5C1A6C7AE41264105": "wcm_v0.2.1_amd64.exe"
            },
        }

        """Returns True of the sha256sum of the executable matches a known release hash.
        """

        @classmethod
        def is_a_release(
            cls, executable_path: str, os: str = platform.system()
        ) -> bool:
            if hashes := cls.SHA256SUMS.get(os):
                with open(executable_path, "rb") as file:
                    hash = hashlib.file_digest(file, "sha256").hexdigest().upper()
                    if hashes.get(hash):
                        return True
                return False
            else:
                KeychainUtilityStorage.__fatal(
                    f"Keychain Storage does not support {os}"
                )

        """Runs the Keychain Utility with the given arguments and returns the output."""

        @classmethod
        def run(
            cls, executable_path: str, args: list[str], check_hash: bool = True
        ) -> str:
            if not cls.is_a_release(executable_path):
                message = f"Keychain Utility '{executable_path}' is not a known release"
                if check_hash:
                    KeychainUtilityStorage.__fatal(message)
                logger.warning(message)
            try:
                args.insert(0, executable_path)
                return (
                    subprocess.run(
                        args,
                        capture_output=True,
                        check=True, # so it raises an exception if return code is not 0
                        executable=executable_path,
                    )
                    .stdout.decode()
                    .strip()
                )
            except subprocess.CalledProcessError as e:
                message = f"Keychain Utility exited with {e.returncode}"
                if e.stderr:
                    message += f" with error output '{e.stderr.decode().strip()}'"
                KeychainUtilityStorage.__fatal(message, e)

    @classmethod
    def __fatal(cls, message: str, error: Exception = None):
        message = f"{cls.__name__}: {message}"
        logger.error(message, error)
        raise exceptions.KeeperError(message, error)

    def __init__(
        self,
        secret_name: str,
        keychain_utility_path: str = None,
        check_keychain_utility_hash: bool = True,
    ):
        if not secret_name:
            self.__fatal("Keychain Utility Storage requires a secret name")
        self.secret_name = secret_name
        logger.debug(f"Keychain Utility Storage using secret name: {self.secret_name}")

        if keychain_utility_path:
            if p := os.path.abspath(keychain_utility_path).strip():
                if os.path.exists(p):
                    self.keychain_utility_path = p
                    logger.debug(
                        f"Keychain Utility Storage using utility at: {self.keychain_utility_path}"
                    )
            else:
                self.__fatal(f"Invalid Keychain Utility path: {keychain_utility_path}")
        elif p := os.getenv("KSM_CONFIG_KEYCHAIN_UTILITY_PATH"):
            if os.path.exists(p):
                logger.debug(
                    f"Using Keychain Utility path from KSM_CONFIG_KEYCHAIN_UTILITY_PATH: {p}"
                )
                self.keychain_utility_path = p
            else:
                self.__fatal(
                    f"Invalid Keychain Utility path in KSM_CONFIG_KEYCHAIN_UTILITY_PATH: {p}"
                )
        else:
            self.__fatal("No Keychain Utility")

        self.check_keychain_utility_hash = check_keychain_utility_hash
        self.config = {}
        self.config_hash = None
        self.__load_config()

    def __run_keychain_utility(self, args: list[str]) -> str:
        return self.KeychainUtility.run(
            self.keychain_utility_path,
            args,
            self.check_keychain_utility_hash,
        )

    # low level hepler methods to do actual read/write
    def __load_config(self):
        try:
            contents = self.__run_keychain_utility(["get", self.secret_name])
            if is_base64(contents):
                contents = url_safe_str_to_bytes(contents)
            if is_json(contents):
                self.config = json.loads(contents)
                self.config_hash = hashlib.md5(
                    json.dumps(self.config, indent=4, sort_keys=True).encode()
                ).hexdigest()
            else:
                self.__fatal(
                    f"Unable to parse Keychain Utility 'get' output as JSON: '{contents}'"
                )

        except Exception as e:
            logger.error(f"Failed to load config JSON from Keychain utlity: {str(e)}")

    def __save_config(self, updated_config: dict = None, force: bool = False):
        if updated_config:
            config = json.dumps(updated_config, indent=4, sort_keys=True)
            hash = hashlib.md5(config.encode()).hexdigest()
            if hash != self.config_hash or force:
                try:
                    self.__run_keychain_utility(["set", self.secret_name, config])
                except Exception as e:
                    logger.error(
                        f"Failed to save config JSON to Keychain utility: {str(e)}"
                    )
                self.config_hash = hash
                self.config = dict(updated_config)
            else:
                logger.warning("Skipped config JSON save. No changes detected.")
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
            logger.debug(f"Removed key {kv}")
        else:
            logger.debug(f"No key {kv} was found in config")

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
