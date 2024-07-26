import base64
import json
import logging
import os
import platform
import subprocess

from core.keeper_secrets_manager_core import exceptions
from core.keeper_secrets_manager_core.configkeys import ConfigKeys
from core.keeper_secrets_manager_core.storage import KeyValueStorage
from core.keeper_secrets_manager_core.keeper_globals import logger_name
from core.keeper_secrets_manager_core.utils import base64_to_string, json_to_dict


class SecureOSStorage(KeyValueStorage):
    """Secure OS based implementation of the key value storage
    
    Uses either the Windows Credential Manager, Linux Keyring or macOS Keychain to store 
    the config. The config is stored as a base64 encoded string.
    """
    def __init__(self, app_name, exec_path):
        if not app_name:
            logging.getLogger(logger_name).error("An application name is required for SecureOSStorage")
            raise exceptions.KeeperError("An application name is required for SecureOSStorage")

        self.app_name = app_name
        self._machine_os = platform.system()
        
        if not exec_path:
            self._exec_path = self._find_exe_path()
            if not self._exec_path:
                logging.getLogger(logger_name).error("Could not find secure config executable")
                raise exceptions.KeeperError("Could not find secure config executable")
        else:
            self._exec_path = exec_path

        self.config = {}

    def _find_exe_path(self) -> str | None:
        if path := os.getenv("KSM_CONFIG_EXE_PATH"):
            return path
        
        if self._machine_os == "Windows":
            return self._run_command(["powershell", "-command", "(Get-Command wcm).Source"])                
        elif self._machine_os == "Linux":
            return self._run_command(["which", "lku"])
            
    def _run_command(self, args: list[str | list]) -> str:
        """Run a command and return the output of stdout."""

        # Flatten args list in instance that it has nested lists
        args_list = [item for arg in args for item in (arg if isinstance(arg, list) else [arg])]

        try:
            completed_process = subprocess.run(args_list, capture_output=True, check=True)
            if completed_process.stdout:
                return completed_process.stdout.decode().strip()
            else:
                # Some commands do not return anything to stdout on success, such as the 'set' command.
                if completed_process.returncode == 0:
                    return ""
                else:
                    logging.getLogger(logger_name).error(
                        f"Failed to run command: {args_list}, which returned {completed_process.stderr}"
                    )
                    raise exceptions.KeeperError(f"Command: {args_list} returned empty stdout")

        except subprocess.CalledProcessError:
            logging.getLogger(logger_name).error(f"Failed to run command: {args_list}")
            raise exceptions.KeeperError(f"Failed to run command: {args_list}")

    def read_storage(self) -> dict:
        result = self._run_command([self._exec_path, "get", self.app_name])
        if not result:
            logging.getLogger(logger_name).error("Failed to read config or config does not exist")
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
