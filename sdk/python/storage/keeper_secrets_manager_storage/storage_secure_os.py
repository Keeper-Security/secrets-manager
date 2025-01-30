import base64
import hashlib
import json
import logging
import os
import platform
import subprocess
from enum import Enum

from keeper_secrets_manager_core import exceptions
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_string, json_to_dict


class LKUChecksums(Enum):
    """Checksums for the Linux Keyring Utility (lku)"""

    V0_1_0 = "3B8AB72D5BE95B4FDD3D56A5ECD6C75EF121CCC36520341B61B8E6DEDBFB5128"
    V0_1_1 = "5C9848AAB7ABCC1842C941D6EB42A55E0C2AD140E5D8F94CA798DF1B336ECFDF"


class WCMChecksums(Enum):
    """Checksums for the Windows Credential Manager Utility (wcm)"""

    V0_1_0 = "50A431188DDBFA7D963304D6ED3B0C6D0B68A0B0703DE0D96C2BB4D0FB2F77F4"
    V0_2_0 = "A166E71F02FE51B5AA132E8664EF4A8922F42AA889E0962DCE5F7ABAD5DCDA0A"
    V0_2_1 = "8EAEB30AE5DEC8F1C3D957C3BC0433D8F18FCC03E5C761A5C1A6C7AE41264105"


def is_valid_checksum(file: str, checksums) -> bool:
    with open(file, "rb") as f:
        file_hash = hashlib.file_digest(f, "sha256")

    for checksum in checksums:
        if file_hash.hexdigest().upper() == checksum.value:
            return True
    return False


class SecureOSStorage(KeyValueStorage):
    """Secure OS based implementation of the key value storage

    Uses either the Windows Credential Manager, Linux Keyring or macOS Keychain to store
    the config. The config is stored as a base64 encoded string.
    """

    def __init__(
        self,
        app_name: str,
        exec_path: str,
        run_as: str = None,
        _lku_checksums=LKUChecksums,
        _wcm_checksums=WCMChecksums,
    ):
        if not app_name:
            logging.getLogger(logger_name).error(
                "An application name is required for SecureOSStorage"
            )
            raise exceptions.KeeperError(
                "An application name is required for SecureOSStorage"
            )

        self.app_name = app_name
        self.lku_checksums = _lku_checksums
        self.wcm_checksums = _wcm_checksums
        self._run_as = run_as
        self._machine_os = platform.system()

        if not exec_path:
            self._exec_path = self._find_exe_path()
            if not self._exec_path:
                logging.getLogger(logger_name).error(
                    "Could not find secure config executable"
                )
                raise exceptions.KeeperError("Could not find secure config executable")
        else:
            self._exec_path = exec_path

        self.config = {}

    def _find_exe_path(self) -> str | None:
        if path := os.getenv("KSM_CONFIG_EXE_PATH"):
            return path

        if self._machine_os == "Windows":
            return self._run_command(
                ["powershell", "-command", "(Get-Command wcm).Source"]
            )
        elif self._machine_os == "Linux":
            return self._run_command(["which", "lku"])

    def _run_command(self, args: list[str]) -> str:
        """Run a command and return the output of stdout."""

        # Check if the checksum of the executable is valid every time it is called, as
        # self._exec_path could be changed during the lifetime of the object.
        if self._machine_os == "Windows":
            valid = is_valid_checksum(self._exec_path, self.wcm_checksums)
        elif self._machine_os == "Linux":
            valid = is_valid_checksum(self._exec_path, self.lku_checksums)
        else:
            valid = False

        if not valid:
            logging.getLogger(logger_name).error(
                f"Checksum for {self._exec_path} is invalid"
            )
            raise exceptions.KeeperError(f"Checksum for {self._exec_path} is invalid")

        # Insert the run_as command at the beginning of the args list if it exists
        if self._run_as:
            args.insert(0, self._run_as)

        try:
            completed_process = subprocess.run(args, capture_output=True, check=True)
            if completed_process.stdout:
                return completed_process.stdout.decode().strip()
            else:
                # Some commands do not return anything to stdout on success, such as the 'set' command.
                if completed_process.returncode == 0:
                    return ""
                else:
                    logging.getLogger(logger_name).error(
                        f"Failed to run command: {args}, which returned {completed_process.stderr}"
                    )
                    raise exceptions.KeeperError(
                        f"Command: {args} returned empty stdout"
                    )

        except subprocess.CalledProcessError:
            logging.getLogger(logger_name).error(f"Failed to run command: {args}")
            raise exceptions.KeeperError(f"Failed to run command: {args}")

    def read_storage(self) -> dict:
        result = self._run_command([self._exec_path, "get", self.app_name])
        if not result:
            logging.getLogger(logger_name).error(
                "Failed to read config or config does not exist"
            )
            return self.config

        config = json_to_dict(base64_to_string(result))
        for key in config:
            self.config[ConfigKeys.get_enum(key)] = config[key]
        return self.config

    def save_storage(self) -> None:
        # Convert current self.config to base64 and save it
        b64_config = base64.b64encode(json.dumps(self.config).encode())
        result = self._run_command([self._exec_path, "set", self.app_name, b64_config])
        if result == "":
            logging.getLogger(logger_name).info("Config saved successfully")

    def get(self, key: ConfigKeys):
        return self.config.get(key)

    def set(self, key: ConfigKeys, value):
        self.config[key] = value

    def delete(self, key: ConfigKeys):
        self.config.pop(key, None)

    def delete_all(self):
        self.config = {}

    def contains(self, key: ConfigKeys):
        return key in self.config
