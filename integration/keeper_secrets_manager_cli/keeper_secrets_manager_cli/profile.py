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

import os
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
from .table import Table, ColumnAlign
from .export import Export
from .config import Config
from .common import find_ksm_path
from colorama import Fore
import sys
import json
import base64


class Profile:

    default_profile = os.environ.get("KSM_CLI_PROFILE", "_default")

    def __init__(self, cli, ini_file=None, config=None, use_keyring=None):
        from .keyring_config import KeyringConfigStorage

        self.cli = cli
        self.ini_file = None
        self.has_profiles = False

        if config is not None:
            self._config = config
        else:
            self._config = Config()

        # If ini_file is explicitly specified, use it
        if ini_file is not None:
            self.use_keyring = False
            self.keyring_storage = None
            self._config = Config(ini_file=ini_file)
            self._config.load()
            self.ini_file = self._config
        # Check environment variables first
        elif os.environ.get("KSM_CONFIG") is not None:
            self.use_keyring = False
            self.keyring_storage = None
            self._config.clear()
            self._config.set_profile_using_base64(Profile.default_profile, os.environ.get("KSM_CONFIG"))
        elif os.environ.get("KSM_CONFIG_BASE64_1") is not None:
            self.use_keyring = False
            self.keyring_storage = None
            self._auto_config_from_env_var(self._config)
        elif os.environ.get("KSM_TOKEN") is not None:
            self.use_keyring = False
            self.keyring_storage = None
            Profile.init(
                token=os.environ.get("KSM_TOKEN"),
                server=os.environ.get("KSM_HOSTNAME", "US"),
                ini_file=ini_file,
                launched_from_app=self._config.launched_from_app
            )
        else:
            found_ini_file = self._find_ini_file()
            
            if found_ini_file is not None:
                self.use_keyring = False
                self.keyring_storage = None
                self._config = Config(ini_file=found_ini_file)
                self._config.load()
                self.ini_file = self._config
            elif use_keyring is not None:
                self.use_keyring = use_keyring
                self.keyring_storage = KeyringConfigStorage() if self.use_keyring else None
                if self.use_keyring:
                    try:
                        self._load_from_keyring()
                    except Exception:
                        pass
            elif KeyringConfigStorage.is_available():
                self.use_keyring = True
                self.keyring_storage = KeyringConfigStorage()
                try:
                    self._load_from_keyring()
                except Exception:
                    pass
            else:
                # No storage available
                self.use_keyring = False
                self.keyring_storage = None

        self.has_profiles = len(self._config.profile_list()) > 0
    
    def _find_ini_file(self):
        """Find keeper.ini file in current directory or standard locations."""
        if os.path.exists("keeper.ini"):
            return os.path.abspath("keeper.ini")
        
        # Check current working directory with absolute path
        cwd_ini = os.path.join(os.getcwd(), "keeper.ini")
        if os.path.exists(cwd_ini):
            return cwd_ini
        
        # Check standard locations
        found = find_ksm_path(Config.default_ini_file)
        if found is not None:
            return found
        
        return None
    
    def _load_from_keyring(self):
        """Load configuration from keyring storage."""
        if not self.keyring_storage:
            return
        
        # Load common config
        common_config = self.keyring_storage.load_common_config()
        if common_config:
            self._config.config.active_profile = common_config.get("active_profile")
            if "color" in common_config:
                self._config.config.color = common_config.get("color")
            if "cache" in common_config:
                self._config.config.cache = common_config.get("cache")
            if "record_type_dir" in common_config:
                self._config.config.record_type_dir = common_config.get("record_type_dir")
            if "editor" in common_config:
                self._config.config.editor = common_config.get("editor")
            if "editor_use_blocking" in common_config:
                self._config.config.editor_use_blocking = common_config.get("editor_use_blocking")
            if "editor_process_name" in common_config:
                self._config.config.editor_process_name = common_config.get("editor_process_name")
        
        # Load all profiles
        profile_names = self.keyring_storage.list_profiles()
        for profile_name in profile_names:
            profile_data = self.keyring_storage.load_profile(profile_name)
            if profile_data:
                self._config.set_profile(profile_name,
                                       client_id=profile_data.get("clientId"),
                                       private_key=profile_data.get("privateKey"),
                                       app_key=profile_data.get("appKey"),
                                       hostname=profile_data.get("hostname"),
                                       app_owner_public_key=profile_data.get("appOwnerPublicKey"),
                                       server_public_key_id=profile_data.get("serverPublicKeyId"))
    
    def _save_common_to_keyring(self):
        """Helper to save common config to keyring."""
        if self.use_keyring and self.keyring_storage:
            common_data = {
                "active_profile": self._config.config.active_profile,
                "color": self._config.config.color,
                "cache": self._config.config.cache,
            }
            if self._config.config.record_type_dir:
                common_data["record_type_dir"] = self._config.config.record_type_dir
            if self._config.config.editor:
                common_data["editor"] = self._config.config.editor
                common_data["editor_use_blocking"] = self._config.config.editor_use_blocking
                common_data["editor_process_name"] = self._config.config.editor_process_name
            
            # Get existing profiles list
            existing = self.keyring_storage.load_common_config() or {}
            if "profiles" in existing:
                common_data["profiles"] = existing["profiles"]
            
            self.keyring_storage.save_common_config(common_data)
    
    def _reload_config(self):
        """Reload configuration from storage (keyring or file).
        
        Uses dynamic detection: checks for INI file first, then keyring.
        """
        from .keyring_config import KeyringConfigStorage
        
        # First, check if INI file exists (takes priority)
        ini_file = self._find_ini_file()
        
        if ini_file is not None:
            # INI file found - use file storage
            self.use_keyring = False
            self.keyring_storage = None
            self._config.ini_file = ini_file
            self._config.has_config_file = True
            self._config._profiles = {}
            self._config.load()
        elif self.use_keyring and self.keyring_storage:
            # No INI file, reload from keyring
            self._config._profiles = {}
            self._load_from_keyring()
        elif KeyringConfigStorage.is_available():
            # Try keyring as fallback
            self.use_keyring = True
            self.keyring_storage = KeyringConfigStorage()
            self._config._profiles = {}
            try:
                self._load_from_keyring()
            except Exception:
                pass
        
        self.has_profiles = len(self._config.profile_list()) > 0

    @staticmethod
    def _auto_config_from_env_var(config):

        """Build config from a Base64 config in environmental variables.

        """

        # Remove any existing configuration.
        config.clear()

        index = 1
        while True:
            config_base64 = os.environ.get("KSM_CONFIG_BASE64_{}".format(index))
            if config_base64 is not None:
                profile_name = os.environ.get("KSM_CONFIG_BASE64_DESC_{}".format(index), "App{}".format(index))
                config.set_profile_using_base64(profile_name, config_base64)
            else:
                break
            index += 1
        config.config.active_profile = os.environ.get("KSM_CONFIG_BASE64_DESC_1", "App1")

    def get_active_profile_name(self):
        return os.environ.get("KSM_CLI_PROFILE", self._config.config.active_profile)

    def get_profile_config(self, profile_name):
        return self._config.get_profile(profile_name)

    def get_common_config(self):
        return self._config.config

    @staticmethod
    def init(token, ini_file=None, server=None, profile_name=None, launched_from_app=False, use_config_file=False):

        from . import KeeperCli
        from .keyring_config import KeyringConfigStorage

        # Determine storage: use file if --config specified, otherwise keyring
        use_keyring = not use_config_file and KeyringConfigStorage.is_available()

        # If the ini is not set, default the file in the current directory.
        if ini_file is None and use_config_file:
            ini_file = Config.get_default_ini_file(launched_from_app)

        if profile_name is None:
            profile_name = os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)

        if profile_name == Config.CONFIG_KEY:
            raise KsmCliException("The profile '{}' is a reserved profile name. Cannot not init profile.".format(
                profile_name))

        # Only create Config object if using file storage
        config = None
        created_ini = False
        
        if use_config_file:
            config = Config(ini_file=ini_file)
            if os.path.exists(ini_file) is True:
                config.load()

        # if the token has a ":" in it, the region code/server is concat'd to the token. Split them.
        if ":" in token:
            server, token = token.split(":", 1)

        config_storage = InMemoryKeyValueStorage()
        config_storage.set(ConfigKeys.KEY_CLIENT_KEY, token)
        if server is not None:
            config_storage.set(ConfigKeys.KEY_HOSTNAME, server)

        client = KeeperCli.get_client(config=config_storage)

        # Get the secret records to get the app key. The SDK will add the app key to the config.
        try:
            client.get_secrets(["AAAAAAAAAAAAAAAAAAAAAA"])
        except (KeeperError, KeeperAccessDenied) as err:
            # If we just create the INI file and there was an error. Remove it.
            if created_ini is True and ini_file:
                os.unlink(ini_file)
            raise KsmCliException("Could not init the profile: {}".format(err.message))
        except Exception as err:
            if created_ini is True and ini_file:
                os.unlink(ini_file)
            raise KsmCliException("Could not init the profile: {}".format(err))

        config_storage = client.config

        import platform
        os_name = platform.system().lower()
        
        # Helper to get secure storage name based on OS
        def get_secure_storage_name():
            if os_name == "darwin":
                return "macOS Keychain"
            elif os_name == "windows":
                return "Windows Credential Manager"
            else:
                return "system keyring"

        # Save to keyring or INI file
        if use_keyring:
            # Check if keeper.ini file exists - block if it does
            default_ini = Config.get_default_ini_file(launched_from_app)
            # Also check current directory
            local_ini = "keeper.ini"
            existing_ini = None
            if os.path.exists(default_ini):
                existing_ini = default_ini
            elif os.path.exists(local_ini):
                existing_ini = os.path.abspath(local_ini)
            
            if existing_ini:
                raise KsmCliException(
                    f"\nA keeper.ini file already exists at: {existing_ini}\n\n"
                    f"To store credentials in {get_secure_storage_name()}, please delete the keeper.ini file first:\n"
                    f"  rm {existing_ini}\n\n"
                    f"Or, to continue using the INI file, use the --ini-file flag:\n"
                    f"  profile init --ini-file {existing_ini} --token <your-token>"
                )
            
            try:
                keyring_storage = KeyringConfigStorage()
                profile_data = {
                    "clientId": config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                    "privateKey": config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                    "appKey": config_storage.get(ConfigKeys.KEY_APP_KEY),
                    "hostname": config_storage.get(ConfigKeys.KEY_HOSTNAME),
                    "appOwnerPublicKey": config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                    "serverPublicKeyId": config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID)
                }
                keyring_storage.save_profile(profile_name, profile_data)
                keyring_storage.add_profile_to_list(profile_name)
                
                # Set active profile in common config
                common_config = keyring_storage.load_common_config() or {}
                common_config["active_profile"] = profile_name
                keyring_storage.save_common_config(common_config)
                
                if os_name == "darwin":
                    print(f"✓ Added profile {profile_name} to macOS Keychain", file=sys.stderr)
                    print("  No keeper.ini file will be created - credentials stored securely in Keychain", file=sys.stderr)
                elif os_name == "windows":
                    print(f"✓ Added profile {profile_name} to Windows Credential Manager", file=sys.stderr)
                    print("  No keeper.ini file will be created - credentials stored securely", file=sys.stderr)
                else:
                    print(f"✓ Added profile {profile_name} to system keyring", file=sys.stderr)
                    print("  No keeper.ini file will be created - credentials stored securely", file=sys.stderr)
            except KsmCliException:
                raise
            except Exception as e:
                raise KsmCliException("Failed to save profile to keyring: {}".format(e))
        else:
            # User is using INI file storage - block if keychain has profiles
            if KeyringConfigStorage.is_available():
                try:
                    keyring_storage = KeyringConfigStorage()
                    existing_profiles = keyring_storage.list_profiles()
                    if existing_profiles:
                        profiles_str = ", ".join(existing_profiles)
                        raise KsmCliException(
                            f"\nYou have existing profiles in {get_secure_storage_name()}: {profiles_str}\n\n"
                            f"To store credentials in an INI file, please delete the existing profiles from {get_secure_storage_name()} first.\n\n"
                            f"Or, to continue using {get_secure_storage_name()}, run without --ini-file:\n"
                            f"  profile init --token <your-token>"
                        )
                except KsmCliException:
                    raise
                except Exception:
                    pass
            
            config.set_profile(profile_name,
                               client_id=config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                               private_key=config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                               app_key=config_storage.get(ConfigKeys.KEY_APP_KEY),
                               hostname=config_storage.get(ConfigKeys.KEY_HOSTNAME),
                               app_owner_public_key=config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                               server_public_key_id=config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

            if config.config.active_profile is None:
                config.config.active_profile = profile_name

            config.save()

            print("✓ Added profile {} to INI config file located at {}".format(profile_name, ini_file), file=sys.stderr)

    @staticmethod
    def from_aws_ec2instance(secret: str, fallback=False, ini_file=None, profile_name=None, launched_from_app=False):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        ini_file = ini_file or Config.get_default_ini_file(launched_from_app)

        profile_name = profile_name or os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)
        if profile_name == Config.CONFIG_KEY:
            raise KsmCliException(f"The profile '{profile_name}' is a reserved"
                                  " profile name. Cannot not init profile.")

        config = Config(ini_file=ini_file)
        if os.path.exists(ini_file) is True:
            config.load()

        awsp = AwsConfigProvider(secret)
        awsp.from_ec2instance_config(secret, fallback)
        cfg = awsp.read_config()
        if not cfg:
            raise KsmCliException(f"Failed to load profile from AWS secret '{secret}'")
        config_storage = InMemoryKeyValueStorage(cfg)

        storage_cfg: dict = {"provider": "ec2instance"}
        if secret:
            storage_cfg["secret"] = secret
        if fallback:
            storage_cfg["fallback"] = fallback

        config.set_profile(profile_name,
                           storage="aws",
                           storage_config=storage_cfg,
                           client_id=config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                           private_key=config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                           app_key=config_storage.get(ConfigKeys.KEY_APP_KEY),
                           hostname=config_storage.get(ConfigKeys.KEY_HOSTNAME),
                           app_owner_public_key=config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                           server_public_key_id=config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

        if config.config.active_profile is None:
            config.config.active_profile = profile_name

        config.save()
        print(f"Added profile {profile_name} to INI config file located at {ini_file}", file=sys.stderr)

    @staticmethod
    def from_aws_profile(secret: str, fallback=False, aws_profile: str = "", ini_file=None, profile_name=None, launched_from_app=False):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        ini_file = ini_file or Config.get_default_ini_file(launched_from_app)

        profile_name = profile_name or os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)
        if profile_name == Config.CONFIG_KEY:
            raise KsmCliException(f"The profile '{profile_name}' is a reserved"
                                  " profile name. Cannot not init profile.")

        config = Config(ini_file=ini_file)
        if os.path.exists(ini_file) is True:
            config.load()

        awsp = AwsConfigProvider(secret)
        if aws_profile:
            awsp.from_profile_config(secret, aws_profile, fallback)
        else:
            awsp.from_default_config(secret, fallback)
        cfg = awsp.read_config()
        if not cfg:
            raise KsmCliException(f"Failed to load profile from AWS secret '{secret}'")
        config_storage = InMemoryKeyValueStorage(cfg)

        storage_cfg: dict = {"provider": "profile"}
        storage_cfg["profile"] = aws_profile or ""
        if secret:
            storage_cfg["secret"] = secret
        if fallback:
            storage_cfg["fallback"] = fallback

        config.set_profile(profile_name,
                           storage="aws",
                           storage_config=storage_cfg,
                           client_id=config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                           private_key=config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                           app_key=config_storage.get(ConfigKeys.KEY_APP_KEY),
                           hostname=config_storage.get(ConfigKeys.KEY_HOSTNAME),
                           app_owner_public_key=config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                           server_public_key_id=config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

        if config.config.active_profile is None:
            config.config.active_profile = profile_name

        config.save()
        print(f"Added profile {profile_name} to INI config file located at {ini_file}", file=sys.stderr)

    @staticmethod
    def from_aws_custom(secret: str, fallback=False,
                        aws_access_key_id: str = "",
                        aws_secret_access_key: str = "",
                        region: str = "",
                        ini_file=None, profile_name=None, launched_from_app=False):
        from keeper_secrets_manager_storage.storage_aws_secret import AwsConfigProvider

        ini_file = ini_file or Config.get_default_ini_file(launched_from_app)

        profile_name = profile_name or os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)
        if profile_name == Config.CONFIG_KEY:
            raise KsmCliException(f"The profile '{profile_name}' is a reserved"
                                  " profile name. Cannot not init profile.")

        config = Config(ini_file=ini_file)
        if os.path.exists(ini_file) is True:
            config.load()

        awsp = AwsConfigProvider(secret)
        awsp.from_custom_config(secret, aws_access_key_id, aws_secret_access_key, region, fallback)
        cfg = awsp.read_config()
        if not cfg:
            raise KsmCliException(f"Failed to load profile from AWS secret '{secret}'")
        config_storage = InMemoryKeyValueStorage(cfg)

        storage_cfg: dict = {"provider": "custom"}
        storage_cfg["aws_access_key_id"] = aws_access_key_id
        storage_cfg["aws_secret_access_key"] = aws_secret_access_key
        storage_cfg["region"] = region
        if secret:
            storage_cfg["secret"] = secret
        if fallback:
            storage_cfg["fallback"] = fallback

        config.set_profile(profile_name,
                           storage="aws",
                           storage_config=storage_cfg,
                           client_id=config_storage.get(ConfigKeys.KEY_CLIENT_ID),
                           private_key=config_storage.get(ConfigKeys.KEY_PRIVATE_KEY),
                           app_key=config_storage.get(ConfigKeys.KEY_APP_KEY),
                           hostname=config_storage.get(ConfigKeys.KEY_HOSTNAME),
                           app_owner_public_key=config_storage.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY),
                           server_public_key_id=config_storage.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID))

        if config.config.active_profile is None:
            config.config.active_profile = profile_name

        config.save()
        print(f"Added profile {profile_name} to INI config file located at {ini_file}", file=sys.stderr)

    def list_profiles(self, output='text', use_color=None):
        
        # Reload config to get latest profiles
        self._reload_config()

        if use_color is None:
            use_color = self.cli.use_color

        profiles = []

        try:
            for profile in self._config.profile_list():
                profiles.append({
                    "active": profile == self._config.config.active_profile,
                    "name": profile
                })

            if output == 'text':
                table = Table(use_color=use_color)
                table.add_column("Active", align=ColumnAlign.CENTER, data_color=Fore.RED)
                table.add_column("Profile", data_color=Fore.YELLOW)

                for profile in profiles:
                    table.add_row(["*" if profile["active"] is True else " ", profile["name"]])

                self.cli.output("\n" + table.get_string() + "\n")
            elif output == 'json':
                self.cli.output(json.dumps(profiles))
            return profiles

        except FileNotFoundError as err:
            raise KsmCliException("Cannot get list of profiles. {}".format(err))

    def set_active(self, profile_name):
        
        # Reload to get latest profiles
        self._reload_config()

        if self._config.get_profile(profile_name) is None:
            raise KsmCliException("Profile {} does not exists.".format(profile_name))

        self._config.config.active_profile = profile_name
        
        # Save to appropriate storage
        if self.use_keyring and self.keyring_storage:
            self._save_common_to_keyring()
        else:
            self._config.save()

        print("{} is now the active profile.".format(profile_name), file=sys.stderr)

    def export_config(self, profile_name=None, file_format='ini', plain=False):

        """Take a profile from an existing config and make it a stand-alone config.

        This is when you want to pull a single profile from a config and use it
        someplace else, like inside of a Docker image.

        """

        # If the profile name is not set, use the active profile.
        if profile_name is None:
            profile_name = self._config.config.active_profile
        profile_config = self._config.get_profile(profile_name)

        if profile_config.storage in (None, "", "internal"):
            config_str = Export(config=profile_config, file_format=file_format, plain=plain).run()
            self.cli.output(config_str)
        else:
            self.cli.output("Only configs stored internally can be exported. "
                            f" Profile [{profile_name}] "
                            f" has storage={profile_config.storage}")

    @staticmethod
    def import_config(config_base64, file=None, profile_name=None, launched_from_app=False):

        """
        Take base64 config file and write it back to disk.
        This file could be a JSON or a Keeper ini file.
        """

        config_data = base64.urlsafe_b64decode(config_base64.encode())

        # Check if the data is JSON
        is_json = False
        try:
            config_data = json.loads(config_data)
            is_json = True
        except json.JSONDecodeError as _:
            pass

        if file is None:
            file = Config.get_default_ini_file(launched_from_app)

        # If a JSON file was import, convert the JSON to a INI.
        if is_json is True:
            if profile_name is None:
                profile_name = os.environ.get("KSM_CLI_PROFILE", Profile.default_profile)
            config = Config(ini_file=file)

            try:
                # If the file exists attempt to load as INI to merge new config
                config.load()
            except:
                pass  # doesn't exists, inaccessible, or not INI: create new

            config.set_profile_using_base64(
                profile_name=profile_name,
                base64_config=config_base64
            )
            config.save()

        # Else just save the INI. It's in the right format, just save it. No processing needed.
        else:
            if profile_name:
                print("Ignored option --profile-name as incompaible with INI file format that can handle multiple profiles.")
            with open(file, "w") as fh:
                fh.write(config_data.decode())
                fh.close()

        print("Imported config saved to profile {} at {}.".format(profile_name, file), file=sys.stderr)

    def set_color(self, on_off):
        common_config = self._config.config
        common_config.color = str(on_off)
        self.cli.use_color = on_off
        
        if self.use_keyring and self.keyring_storage:
            self._save_common_to_keyring()
        else:
            self._config.save()

    def set_cache(self, on_off):
        common_config = self._config.config
        common_config.cache = str(on_off)
        self.cli.use_cache = on_off
        
        if self.use_keyring and self.keyring_storage:
            self._save_common_to_keyring()
        else:
            self._config.save()

    def set_record_type_dir(self, directory):
        common_config = self._config.config
        if directory is None:
            common_config.record_type_dir = None
        else:
            if os.path.exists(directory) is False:
                raise FileNotFoundError(f"Cannot find the directory 'directory' for record type schemas.")
            common_config.record_type_dir = str(directory)
        self.cli.record_type_dir = directory
        
        if self.use_keyring and self.keyring_storage:
            self._save_common_to_keyring()
        else:
            self._config.save()

    def set_editor(self, editor, use_blocking=None, process_name=None):
        common_config = self._config.config
        if editor is None:
            common_config.editor = None
            common_config.editor_use_blocking = False
            common_config.editor_process_name = None
        else:
            common_config.editor = editor
            if use_blocking is not None:
                common_config.editor_use_blocking = str(use_blocking)
            if process_name is not None:
                common_config.editor_process_name = process_name
        self.cli.editor = editor
        self.cli.editor_use_blocking = use_blocking
        
        if self.use_keyring and self.keyring_storage:
            self._save_common_to_keyring()
        else:
            self._config.save()

    def show_config(self):

        def _check_set(value):
            if value is None:
                return "-NOT SET-"
            return value

        common_config = self._config.config

        table = Table(use_color=self.cli.use_color)
        table.add_column("Config Item", data_color=Fore.GREEN)
        table.add_column("Value", data_color=Fore.YELLOW, allow_wrap=True)

        table.add_row(["Active Profile", _check_set(common_config.active_profile)])
        table.add_row(["Cache Enabled", _check_set(common_config.cache)])
        table.add_row(["Color Enabled", _check_set(common_config.color)])
        table.add_row(["Record Type Directory", _check_set(common_config.record_type_dir)])
        table.add_row(["Editor", "{} ({})".format(_check_set(common_config.editor),
                                                  _check_set(common_config.editor_process_name))])
        table.add_row(["Editor Blocking", _check_set(common_config.editor_use_blocking)])
        self.cli.output(table.get_string())
