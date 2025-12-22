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
import os
import logging
from typing import Dict, Optional

from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.storage import KeyringUtilityStorage
from keeper_secrets_manager_cli.exception import KsmCliException


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
        
    def _get_storage(self, secret_name: str) -> KeyringUtilityStorage:
        """Get a KeyringUtilityStorage instance for a specific secret."""
        try:
            return KeyringUtilityStorage(
                secret_name=secret_name,
                keyring_application_name=self.keyring_application_name
            )
        except Exception as e:
            raise KsmCliException(f"Failed to initialize keyring storage: {e}")
    
    def save_common_config(self, config_data: Dict) -> None:
        """Save common configuration to keyring."""
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            config_json = json.dumps(config_data)
            storage.save_storage({"data": config_json})
            self.logger.info(f"Saved common config to keyring: {self.COMMON_SECRET}")
        except Exception as e:
            raise KsmCliException(f"Failed to save common config to keyring: {e}")
    
    def load_common_config(self) -> Optional[Dict]:
        """Load common configuration from keyring."""
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            data = storage.read_storage()
            if data and "data" in data:
                return json.loads(data["data"])
            return None
        except Exception as e:
            self.logger.debug(f"Could not load common config from keyring: {e}")
            return None
    
    def save_profile(self, profile_name: str, profile_data: Dict) -> None:
        """Save a profile configuration to keyring."""
        try:
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
            storage = self._get_storage(secret_name)
            config_json = json.dumps(profile_data)
            storage.save_storage({"data": config_json})
            self.logger.info(f"Saved profile '{profile_name}' to keyring: {secret_name}")
        except Exception as e:
            raise KsmCliException(f"Failed to save profile '{profile_name}' to keyring: {e}")
    
    def load_profile(self, profile_name: str) -> Optional[Dict]:
        """Load a profile configuration from keyring."""
        try:
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
            storage = self._get_storage(secret_name)
            data = storage.read_storage()
            if data and "data" in data:
                return json.loads(data["data"])
            return None
        except Exception as e:
            self.logger.debug(f"Could not load profile '{profile_name}' from keyring: {e}")
            return None
    
    def list_profiles(self) -> list:
        """List all profiles stored in keyring."""
        # Note: KeyringUtilityStorage doesn't have a list function
        # We'll need to track profiles in the common config
        common = self.load_common_config()
        if common and "profiles" in common:
            return common["profiles"]
        return []
    
    def delete_profile(self, profile_name: str) -> None:
        """Delete a profile from keyring."""
        try:
            secret_name = f"{self.PROFILE_SECRET_PREFIX}{profile_name}"
            storage = self._get_storage(secret_name)
            storage.delete_all()
            self.logger.info(f"Deleted profile '{profile_name}' from keyring")
            
            # Update profile list in common config
            common = self.load_common_config() or {}
            if "profiles" in common and profile_name in common["profiles"]:
                common["profiles"].remove(profile_name)
                self.save_common_config(common)
        except Exception as e:
            raise KsmCliException(f"Failed to delete profile '{profile_name}' from keyring: {e}")
    
    def add_profile_to_list(self, profile_name: str) -> None:
        """Add a profile name to the tracked list in common config."""
        common = self.load_common_config() or {}
        if "profiles" not in common:
            common["profiles"] = []
        if profile_name not in common["profiles"]:
            common["profiles"].append(profile_name)
        self.save_common_config(common)
    
    def delete_common_config(self) -> None:
        """Delete common configuration from keyring."""
        try:
            storage = self._get_storage(self.COMMON_SECRET)
            storage.delete_all()
            self.logger.info(f"Deleted common config from keyring")
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
            except Exception:
                pass
        
        # Delete common config
        try:
            self.delete_common_config()
        except Exception:
            pass
    
    @staticmethod
    def is_available() -> bool:
        """Check if keyring storage is available on this system."""
        try:
            # Try to import keyring library
            import keyring
            return True
        except Exception:
            return False


