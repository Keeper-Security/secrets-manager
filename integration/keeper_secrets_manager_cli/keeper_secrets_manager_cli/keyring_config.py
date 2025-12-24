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

This module provides secure OS-level storage for CLI profiles using KeyringUtilityStorage.
"""

import json
import re
import logging
from typing import Dict, Optional

from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyringUtilityStorage
from keeper_secrets_manager_cli.exception import KsmCliException


# Profile name validation: alphanumeric, hyphens, underscores, max 64 chars
PROFILE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


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
            raise KsmCliException(f"Failed to initialize keyring storage: {e}")
        except Exception as e:
            self.logger.debug(f"Keyring storage initialization error: {e}")
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
            raise KsmCliException(f"Failed to serialize config data: {e}")
        except Exception as e:
            self.logger.debug(f"Save common config error: {e}")
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
            self.logger.warning(f"Invalid JSON in common config: {e}")
            return None
        except KsmCliException:
            return None
        except Exception as e:
            self.logger.debug(f"Could not load common config from keyring: {e}")
            return None
    
    def save_profile(self, profile_name: str, profile_data: Dict) -> None:
        """Save a profile configuration to keyring."""
        self._validate_profile_name(profile_name)
        if not isinstance(profile_data, dict):
            raise KsmCliException("Profile data must be a dictionary")
        try:
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
            storage = self._get_storage(secret_name)
            config_json = json.dumps(profile_data)
            storage.save_storage({"data": config_json})
            self.logger.debug("Saved profile to keyring")
        except KsmCliException:
            raise
        except (TypeError, ValueError) as e:
            raise KsmCliException(f"Failed to serialize profile data: {e}")
        except Exception as e:
            self.logger.debug(f"Save profile error: {e}")
            raise KsmCliException(f"Failed to save profile '{profile_name}' to keyring")
    
    def load_profile(self, profile_name: str) -> Optional[Dict]:
        """Load a profile configuration from keyring."""
        self._validate_profile_name(profile_name)
        try:
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
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
            self.logger.warning(f"Invalid JSON in profile config: {e}")
            return None
        except KsmCliException:
            return None
        except Exception as e:
            self.logger.debug(f"Could not load profile from keyring: {e}")
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
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
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
            self.logger.debug(f"Delete profile error: {e}")
            raise KsmCliException(f"Failed to delete profile '{profile_name}' from keyring")
    
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
            self.logger.debug(f"Could not delete common config from keyring: {e}")
        except Exception as e:
            self.logger.debug(f"Could not delete common config from keyring: {e}")
    
    def clear_all(self) -> None:
        """Clear all profiles and common config from keyring."""
        # First get all profile names
        profiles = self.list_profiles()
        
        # Delete each profile
        for profile_name in profiles:
            try:
                self.delete_profile(profile_name)
            except KsmCliException as e:
                self.logger.debug(f"Failed to delete profile during clear_all: {e}")
            except Exception as e:
                self.logger.debug(f"Unexpected error deleting profile during clear_all: {e}")
        
        # Delete common config
        self.delete_common_config()
    
    @staticmethod
    def is_available() -> bool:
        """Check if keyring storage is available on this system."""
        try:
            # Try to import keyring library
            import keyring
            return True
        except ImportError:
            return False