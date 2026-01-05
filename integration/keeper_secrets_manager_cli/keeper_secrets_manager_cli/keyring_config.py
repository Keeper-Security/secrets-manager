# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#

"""
Keyring-based configuration storage for KSM CLI.

This module provides secure OS-level storage for CLI profiles.
"""

import json
import re
import logging
import hashlib
import os
import shutil
import subprocess
import base64
from typing import Dict, Optional

from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import exceptions
from keeper_secrets_manager_core.utils import is_base64, url_safe_str_to_bytes
from keeper_secrets_manager_cli.exception import KsmCliException


# Profile name validation: alphanumeric, hyphens, underscores, max 64 chars
PROFILE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


class KeyringUtilityStorage(KeyValueStorage):
    """OS Keyring Storage extends the key value storage interface.

    Uses Python keyring library for cross-platform support:
    - macOS: Keychain
    - Windows: Credential Manager  
    - Linux: Secret Service (or lkru utility as fallback)
    """

    logger = logging.getLogger(logger_name)

    @classmethod
    def __fatal(cls, message: str, error: Exception = None):
        message = f"{cls.__name__}: {message}"
        if error:
            cls.logger.error(message, exc_info=error)
        else:
            cls.logger.error(message)
        raise exceptions.KeeperError(message, error)

    def __init__(
        self,
        secret_name: str,
        keyring_application_name: str = None,
        keyring_collection_name: str = None,
        keyring_utility: str = "lkru",
        keyring_utility_path: str = None,
    ):
        if not secret_name:
            self.__fatal("Keyring Storage requires a secret name")

        self.secret_name = secret_name
        self.keyring_application_name = keyring_application_name or "keeper-secrets-manager"
        self.keyring_collection_name = keyring_collection_name
        
        # Try to use Python keyring library (works on macOS, Windows, Linux)
        self.use_python_keyring = False
        self.keyring_utility_path = None
        
        try:
            import keyring
            self.use_python_keyring = True
            self.logger.debug("Using Python keyring library for OS-native storage")
        except ImportError:
            if keyring_utility_path:
                p = os.path.abspath(keyring_utility_path).strip()
                if p and os.path.exists(p):
                    self.keyring_utility_path = p
                    self.logger.debug("Using lkru utility at: %s", self.keyring_utility_path)
                else:
                    self.__fatal("Invalid keyring utility path: %s" % keyring_utility_path)
            else:
                p = os.getenv("KSM_CONFIG_KEYRING_UTILITY_PATH")
                if p and os.path.exists(p):
                    self.keyring_utility_path = p
                    self.logger.debug("Using lkru from KSM_CONFIG_KEYRING_UTILITY_PATH: %s", p)
                elif p:
                    self.__fatal("Invalid path in KSM_CONFIG_KEYRING_UTILITY_PATH: %s" % p)
                else:
                    p = shutil.which(keyring_utility)
                    if p:
                        self.keyring_utility_path = p
                        self.logger.debug("Using lkru utility at: %s", self.keyring_utility_path)
                    else:
                        self.__fatal("No keyring backend available. Install: pip install keyring")

        self.config = {}
        self.config_hash = None
        self.__load_config()

    def __get_keyring_value(self, key: str) -> str:
        """Get value from keyring (Python library or lkru utility)."""
        if self.use_python_keyring:
            import keyring
            value = keyring.get_password(self.keyring_application_name, key)
            return value if value else ""
        else:
            return self.__run_keyring_utility(["get", key])
    
    def __set_keyring_value(self, key: str, value: str) -> None:
        """Set value in keyring (Python library or lkru utility)."""
        if self.use_python_keyring:
            import keyring
            keyring.set_password(self.keyring_application_name, key, value)
        else:
            self.__run_keyring_utility(["set", key, value])

    def __delete_keyring_value(self, key: str) -> None:
        """Delete value from keyring (Python library or lkru utility)."""
        if self.use_python_keyring:
            import keyring
            try:
                keyring.delete_password(self.keyring_application_name, key)
            except keyring.errors.PasswordDeleteError:
                pass  # Key doesn't exist, that's fine
        else:
            self.__run_keyring_utility(["delete", key])

    def __run_keyring_utility(self, args: list) -> str:
        """Run lkru utility (Linux only fallback)."""
        try:
            # Use if/elif instead of match for Python 3.7 compatibility
            cmd = args[0]
            if cmd == "get" or cmd == "set":
                args.append("-b")

            if self.keyring_application_name:
                args.insert(1, self.keyring_application_name)
                args.insert(1, "-a")

            if self.keyring_collection_name:
                args.insert(1, self.keyring_collection_name)
                args.insert(1, "-c")

            args.insert(0, self.keyring_utility_path)

            self.logger.debug("Running keyring utility as: %s", args)

            return (
                subprocess.run(
                    args,
                    capture_output=True,
                    check=True,
                    executable=self.keyring_utility_path,
                )
                .stdout.decode()
                .strip()
            )
        except subprocess.CalledProcessError as e:
            message = "Keyring utility exited with %d" % e.returncode
            if e.stderr:
                message += " with error output '%s'" % e.stderr.decode().strip()
            self.__fatal(message, e)


    def __load_config(self):
        try:
            from keeper_secrets_manager_core.helpers import is_json
            
            contents = self.__get_keyring_value(self.secret_name)
            if not contents:
                self.config = {}
                return
                
            if is_base64(contents):
                contents = url_safe_str_to_bytes(contents)

            if is_json(contents):
                self.config = json.loads(contents)
                self.config_hash = hashlib.md5(
                    json.dumps(self.config, indent=4, sort_keys=True).encode()
                ).hexdigest()
            else:
                self.__fatal(
                    "Unable to parse keyring output as JSON: '%s'" % contents
                )
        except Exception as e:
            self.logger.debug("No existing config in keyring: %s", str(e))

    def __save_config(self, updated_config: dict = None, force: bool = False):
        if updated_config:
            config = json.dumps(updated_config, indent=4, sort_keys=True)
            hash_value = hashlib.md5(config.encode()).hexdigest()

            if hash_value != self.config_hash or force:
                try:
                    self.__set_keyring_value(self.secret_name, config)
                except Exception as e:
                    self.logger.error(
                        "Failed to save config JSON to keyring: %s", str(e)
                    )

                self.config_hash = hash_value
                self.config = dict(updated_config)
            else:
                self.logger.warning("Skipped config JSON save. No changes detected.")
                return


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
            self.logger.debug("Removed key %s", kv)
        else:
            self.logger.debug("No key %s was found in config", kv)

        self.save_storage(config)
        return config

    def delete_all(self):
        """Delete all config from keyring."""
        try:
            self.__delete_keyring_value(self.secret_name)
            self.config = {}
            self.config_hash = None
        except Exception as e:
            self.logger.debug("Error deleting from keyring: %s", str(e))
        return dict(self.config)

    def contains(self, key: ConfigKeys):
        config = self.read_storage()
        return key.value in config

    def is_empty(self):
        config = self.read_storage()
        return not config


class KeyringConfigStorage:
    """
    Stores CLI configuration in OS keyring instead of keeper.ini file.
    
    Storage format:
    - Common config: secret name = "ksm-cli-common"
    - Profiles: secret name = "ksm-cli-profile-{profile_name}"
    """
    
    COMMON_SECRET = "ksm-cli-common"
    PROFILE_SECRET_PREFIX = "ksm-cli-profile-"
    
    def __init__(self, keyring_application_name: str = "KSM-cli"):
        self.logger = logging.getLogger(logger_name)
        self.keyring_application_name = keyring_application_name
    
    @staticmethod
    def _validate_profile_name(profile_name: str) -> None:
        """Validate profile name to prevent injection and ensure consistency."""
        if not profile_name:
            raise KsmCliException("Profile name cannot be empty")
        if not isinstance(profile_name, str):
            raise KsmCliException("Profile name must be a string")
        if not PROFILE_NAME_PATTERN.match(profile_name):
            raise KsmCliException(
                "Profile name must be 1-64 characters, containing only "
                "alphanumeric characters, hyphens, and underscores"
            )
        
    def _get_storage(self, secret_name: str) -> KeyringUtilityStorage:
        """Get a KeyringUtilityStorage instance for a specific secret."""
        try:
            return KeyringUtilityStorage(
                secret_name=secret_name,
                keyring_application_name=self.keyring_application_name
            )
        except (ValueError, TypeError, OSError) as e:
            raise KsmCliException("Failed to initialize keyring storage: %s" % e)
        except Exception as e:
            self.logger.debug("Keyring storage initialization error: %s", e)
            raise KsmCliException("Failed to initialize keyring storage")
    
    def save_common_config(self, config_data: Dict) -> None:
        """Save common configuration to keyring."""
        if not isinstance(config_data, dict):
            raise KsmCliException("Config data must be a dictionary")
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            config_json = json.dumps(config_data)
            storage.save_storage({"data": config_json})
            self.logger.debug("Saved common config to keyring")
        except KsmCliException:
            raise
        except (TypeError, ValueError) as e:
            raise KsmCliException("Failed to serialize config data: %s" % e)
        except Exception as e:
            self.logger.debug("Save common config error: %s", e)
            raise KsmCliException("Failed to save common config to keyring")
    
    def load_common_config(self) -> Optional[Dict]:
        """Load common configuration from keyring."""
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            data = storage.read_storage()
            if data and "data" in data:
                result = json.loads(data["data"])
                if not isinstance(result, dict):
                    self.logger.warning("Common config data is not a dictionary")
                    return None
                return result
            return None
        except json.JSONDecodeError as e:
            self.logger.warning("Invalid JSON in common config: %s", e)
            return None
        except KsmCliException:
            return None
        except Exception as e:
            self.logger.debug("Could not load common config from keyring: %s", e)
            return None
    
    def save_profile(self, profile_name: str, profile_data: Dict) -> None:
        """Save a profile configuration to keyring."""
        self._validate_profile_name(profile_name)
        if not isinstance(profile_data, dict):
            raise KsmCliException("Profile data must be a dictionary")
        try:
            secret_name = "%s%s" % (self.PROFILE_SECRET_PREFIX, profile_name)
            storage = self._get_storage(secret_name)
            config_json = json.dumps(profile_data)
            storage.save_storage({"data": config_json})
            self.logger.debug("Saved profile to keyring")
        except KsmCliException:
            raise
        except (TypeError, ValueError) as e:
            raise KsmCliException("Failed to serialize profile data: %s" % e)
        except Exception as e:
            self.logger.debug("Save profile error: %s", e)
            raise KsmCliException("Failed to save profile '%s' to keyring" % profile_name)
    
    def load_profile(self, profile_name: str) -> Optional[Dict]:
        """Load a profile configuration from keyring."""
        self._validate_profile_name(profile_name)
        try:
            secret_name = "%s%s" % (self.PROFILE_SECRET_PREFIX, profile_name)
            storage = self._get_storage(secret_name)
            data = storage.read_storage()
            if data and "data" in data:
                result = json.loads(data["data"])
                if not isinstance(result, dict):
                    self.logger.warning("Profile data is not a dictionary")
                    return None
                return result
            return None
        except json.JSONDecodeError as e:
            self.logger.warning("Invalid JSON in profile config: %s", e)
            return None
        except KsmCliException:
            return None
        except Exception as e:
            self.logger.debug("Could not load profile from keyring: %s", e)
            return None
    
    def list_profiles(self) -> list:
        """List all profiles stored in keyring."""
        # Note: KeyringUtilityStorage doesn't have a list function
        # We'll need to track profiles in the common config
        common = self.load_common_config()
        if common and "profiles" in common:
            profiles = common["profiles"]
            if isinstance(profiles, list):
                # Filter to only valid profile names
                return [p for p in profiles if isinstance(p, str) and PROFILE_NAME_PATTERN.match(p)]
        return []
    
    def delete_profile(self, profile_name: str) -> None:
        """Delete a profile from keyring."""
        self._validate_profile_name(profile_name)
        try:
            secret_name = "%s%s" % (self.PROFILE_SECRET_PREFIX, profile_name)
            storage = self._get_storage(secret_name)
            storage.delete_all()
            self.logger.debug("Deleted profile from keyring")
            
            # Update profile list in common config
            common = self.load_common_config() or {}
            if "profiles" in common and profile_name in common["profiles"]:
                common["profiles"].remove(profile_name)
                self.save_common_config(common)
        except KsmCliException:
            raise
        except Exception as e:
            self.logger.debug("Delete profile error: %s", e)
            raise KsmCliException("Failed to delete profile '%s' from keyring" % profile_name)
    
    def add_profile_to_list(self, profile_name: str) -> None:
        """Add a profile name to the tracked list in common config."""
        self._validate_profile_name(profile_name)
        common = self.load_common_config() or {}
        if "profiles" not in common:
            common["profiles"] = []
        if not isinstance(common["profiles"], list):
            common["profiles"] = []
        if profile_name not in common["profiles"]:
            common["profiles"].append(profile_name)
        self.save_common_config(common)
    
    def delete_common_config(self) -> None:
        """Delete common configuration from keyring."""
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            storage.delete_all()
            self.logger.debug("Deleted common config from keyring")
        except KsmCliException as e:
            self.logger.debug("Could not delete common config from keyring: %s", e)
        except Exception as e:
            self.logger.debug("Could not delete common config from keyring: %s", e)
    
    def clear_all(self) -> None:
        """Clear all profiles and common config from keyring."""
        # First get all profile names
        profiles = self.list_profiles()
        
        # Delete each profile
        for profile_name in profiles:
            try:
                self.delete_profile(profile_name)
            except KsmCliException as e:
                self.logger.debug("Failed to delete profile during clear_all: %s", e)
            except Exception as e:
                self.logger.debug("Unexpected error deleting profile during clear_all: %s", e)
        
        # Delete common config
        self.delete_common_config()
    
    @staticmethod
    def is_available() -> bool:
        """Check if keyring is available and working."""
        try:
            import keyring
            backend = keyring.get_keyring()
            
            # Reject fail.Keyring backend (doesn't actually store anything)
            backend_module = backend.__class__.__module__
            if 'fail' in backend_module.lower():
                return False
            
            return True
        except ImportError:
            return False
        except Exception:
            return False
