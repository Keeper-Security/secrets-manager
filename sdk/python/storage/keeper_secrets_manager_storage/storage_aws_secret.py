# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com
"""This module provides classes for working with KSM config
stored in an AWS secret.
"""
import base64
import hashlib
import json
import logging
import os
import re

from enum import Enum
from keeper_secrets_manager_core.helpers import is_json
from keeper_secrets_manager_core.storage import KeyValueStorage
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core.utils import (is_base64, url_safe_str_to_bytes)
from keeper_secrets_manager_storage.config_provider import IConfigProvider

logger = logging.getLogger(logger_name)

try:
    import boto3
    from boto3.session import Session
    from botocore.credentials import InstanceMetadataProvider
    from botocore.exceptions import ClientError
    from botocore.session import get_session
    from botocore.utils import (InstanceMetadataFetcher, IMDSFetcher, IMDSRegionProvider)
except ImportError:
    logger.error("Missing AWS SDK import dependencies."
                 " To install missing packages run: \r\n"
                 "pip3 install boto3\r\n")
    raise Exception("Missing import dependencies: boto3")


class AwsConfigType(Enum):
    """Enumerates AWS configuration types"""
    EC2INSTANCE = 1  # use EC2 instance role permissions
    SESSION = 2      # use default session/profile
    PROFILE = 3      # use profile specified by name
    CREDENTIALS = 4  # use custom credentials


# AwsConfigProvider is used internally by AWS storage provider
# but can also be used separately for ex. to read KSM config from a secret
# and initialize a read only InMemoryKeyValueStorage
class AwsConfigProvider(IConfigProvider):
    """ AWS Secrets Manager based implementation of the config provider

    AwsConfigProvider by default uses Ec2Instance config with
    fallback to default session set to True. To switch to a different
    configuration method use one of its helper methods.

    The provider uses AWS Secrets Manager secret as a storage media
    and requires credentials with proper permissions:
    SecretsManagerReadWrite managed policy or
    a resource-based policy with read/write/create access to the secret

    write_config should be used only once - when config is generated from token
    Once generated/saved KMS configration is static and should be readonly

    If configuration is externally generated (no need for KSM tokens) then
    more restrictive access policy may be applied - ex. allow read only access
    """

    def __init__(self, aws_key: str):
        """ AwsConfigProvider by default uses Ec2Instance config with
        fallback to default session set to True
        To switch to a different configuration method use one of the
        following helper methods:

        - `from_ec2instance_config()` - autodetect and use instance credentials
        with option to fallback to the default session

        - `from_default_config()` - use the default AWS profile

        - `from_profile_config()` - use stored AWS profile with a given name,
        with option to fallback to the default session

        - `from_custom_config()` - use custom AWS credentials
        with option to fallback to the default session

        Parameters:
        aws_key (str): secret name/id or a full ARN
        """

        self._reset(aws_key)

    def _reset(self, aws_key: str):
        """ Resets to default configration: EC2Instance with
        fallback to default session set to True
        """

        # secret name/id or a full ARN
        self.key_name: str = aws_key

        # fallback to default session if initial credentials fail
        self.fallback: bool = True

        # AwsConfigType.SESSION is same as AwsConfigType.PROFILE
        # but without an option to select another non-default profile
        # EC2INSTANCE has no extra params (except its config_type)
        self.config_type: AwsConfigType = AwsConfigType.EC2INSTANCE

        # AwsConfigType.PROFILE only:
        self.aws_profile: str = ""  # use default profile when missing or empty

        # AwsConfigType.CREDENTIALS only:
        self.aws_access_key_id: str = ""
        self.aws_secret_access_key: str = ""
        self.region: str = ""

        # reset any pre-existing session too
        self.bc_session = get_session()  # provides low level access
        self.boto3_session = Session(botocore_session=self.bc_session)

    # Helper methods for creating and initializing different types of
    # AWS config providers ensuring only correct options are used for the
    # specified config type.
    def from_ec2instance_config(self, aws_key: str,
                                fallback_to_default_profile: bool = True):
        """Create config provider using ec2 instance role permissions

        Provider must be used in EC2 instances only - uses instance credentials
        to authenticate and access AWS Secrets Manager to store and retrieve
        the configuration string

        Requires SecretsManagerReadWrite managed policy in the instance role
        arn:aws:iam::aws:policy/SecretsManagerReadWrite
        """

        self._reset(aws_key)
        self.fallback = fallback_to_default_profile
        self.config_type = AwsConfigType.EC2INSTANCE

        # Client requires both AWS credentials and region.
        self._setup_credential_provider()
        self.region = self._get_instance_region()

    def from_default_config(self, aws_key: str,
                            fallback_to_default_profile: bool = True):
        """Create config provider using default session"""

        self._reset(aws_key)
        self.fallback = fallback_to_default_profile
        self.config_type = AwsConfigType.SESSION

    def from_profile_config(self, aws_key: str,
                            profile: str,
                            fallback_to_default_profile: bool = True):
        """Create config provider using named profile"""

        self._reset(aws_key)
        self.fallback = fallback_to_default_profile
        self.config_type = AwsConfigType.PROFILE
        self.aws_profile = profile

    def from_custom_config(self, aws_key: str,
                           aws_access_key_id: str,
                           aws_secret_access_key: str,
                           region: str,
                           fallback_to_default_profile: bool = True):
        """Create config provider using custom access keys"""

        self._reset(aws_key)
        self.fallback = fallback_to_default_profile
        self.config_type = AwsConfigType.CREDENTIALS
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.region = region

    def _get_instance_region(self) -> str:
        """Used by AwsConfigType.EC2INSTANCE to auto-detect the region"""
        # 1. Use ARN: if key contains full ARN - get region from the key
        # arn:partition:service:region:account-id:resource-type:resource-id
        region: str = ""
        match = re.search(r'arn:aws:secretsmanager:(?P<region>[^:]*):', self.key_name, re.IGNORECASE)
        if match:
            arn_region = match.group('region')
            region = arn_region if arn_region else ""

        # Use Instance Metadata Service (IMDS) to retrieve the region
        # 2. Fetch meta-data placement: placement/region released 2020-08-24
        if not region:
            try:
                imds_data = IMDSFetcher()._get_request("/latest/meta-data/placement/region", None)
                if imds_data:
                    region = str(imds_data.text)
            except Exception:
                pass

        # 3. Fetch dynamic instance-identity document
        if not region:
            try:
                imds_data = IMDSFetcher()._get_request("/latest/dynamic/instance-identity/document", None)
                if imds_data:
                    doc = imds_data.text
                    rdic = json.loads(doc)
                    region = rdic.get("region", "") or ""
            except Exception:
                pass

        # 4. Fetch meta-data hostname - only if IP-based naming (IPBN) used
        # ex. ip-192-168-1-1.us-east-2.compute.internal
        # ex. ec2-192-168-0-1.ap-southeast-2.compute.amazonaws.com
        # nb! us-east-1 instances may have a different format without region
        # ex. ip-10-24-34-0.ec2.internal, i-0123456789abcdef.ec2.internal
        if not region:
            try:
                imds_data = IMDSFetcher()._get_request("/latest/meta-data/hostname", None).text
                if imds_data:
                    hostname = str(imds_data.text)
                    match = re.search(r'\.(?P<region>[^.]*)\.compute\.', hostname, re.IGNORECASE)
                    if match:
                        grp_region = match.group('region')
                        region = grp_region if grp_region else ""
            except Exception:
                pass

        # 5. Use IMDSRegionProvider - always last
        # This provider could fallback to env vars which could be set incorrectly
        if not region:
            try:
                irp = IMDSRegionProvider(self.bc_session)
                rgn = irp.provide()
                if rgn and isinstance(rgn, str):
                    region = rgn
            except Exception:
                pass

        return region

    def _setup_credential_provider(self):
        """Used by AwsConfigType.EC2INSTANCE to set up the creds provider"""
        # Keep only existing InstanceMetadataProvider (usually the last one)
        # We will try others (default provider chain) later if fallback=True
        # trying to avoid pitfalls of a local misconfiguration...
        cred_provider = self.bc_session.get_component('credential_provider')
        providers = [x for x in cred_provider.providers if isinstance(x, InstanceMetadataProvider)]
        if not providers:
            imdp = InstanceMetadataProvider(iam_role_fetcher=InstanceMetadataFetcher(timeout=1000, num_attempts=2))
            providers = [imdp]
        cred_provider.providers.clear()
        cred_provider.providers.extend(providers)

    def _get_client(self) -> Session.client:
        """Creates a configured secretsmanager client"""

        try:
            if self.config_type == AwsConfigType.CREDENTIALS:
                secretsmanager = boto3.client('secretsmanager',
                                        aws_access_key_id=self.aws_access_key_id,
                                        aws_secret_access_key=self.aws_secret_access_key,
                                        region_name=self.region)
            elif self.config_type == AwsConfigType.EC2INSTANCE:
                session = self.boto3_session
                secretsmanager = session.client('secretsmanager', region_name=self.region)
            elif self.config_type == AwsConfigType.PROFILE:
                session = Session(botocore_session=self.bc_session, profile_name=self.aws_profile)
                secretsmanager = session.client('secretsmanager')
            else:
                secretsmanager = boto3.client('secretsmanager')  # default profile
            # When run outside of EC2 VM on an unconfigured machine it fails
            # with "Invalid endpoint: https://secretsmanager..amazonaws.com"
        except Exception as ex:
            if self.fallback:
                secretsmanager = boto3.client('secretsmanager')  # default session
            else:
                raise ex  # rethrow

        return secretsmanager

    # Interface methods implementation
    def read_config(self) -> str:
        res = {}
        secretsmanager = self._get_client()

        try:
            res = self._get_secret_aws(secretsmanager, self.key_name)
        except Exception:
            pass

        # if provided credentials failed try using default session/creds
        if (not res or res.get("not_found", False) or res.get("error", "")) and self.fallback is True:
            secretsmanager = boto3.client('secretsmanager')  # default session
            res = self._get_secret_aws(secretsmanager, self.key_name)

        result = res.get("value", "") or "" if res else ""
        return result

    def write_config(self, config: str) -> str:
        res = {}
        secretsmanager = self._get_client()

        try:
            res = self._set_secret_aws(secretsmanager, self.key_name, config)
        except Exception as ex:
            res = {"error": str(ex)}

        # Ignore self.fallback and default session/creds on write
        # to prevent creating secrets in unexpected locations
        result = str(res.get("error", "") or "") if res else ""
        return result

    # low level hepler methods to do actual read/write
    def _get_secret_aws(self, client, key: str):
        """Read AWS secret using the provided client and secret key"""
        result = {
            "value": None,
            "not_found": False,
            "error": None
        }

        try:
            get_secret_value_response = client.get_secret_value(SecretId=key)
            if 'SecretString' in get_secret_value_response:
                result["value"] = get_secret_value_response['SecretString']
            elif 'SecretBinary' in get_secret_value_response:
                result["value"] = base64.b64decode(get_secret_value_response['SecretBinary'])
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = e.response.get('Error', {}).get('Message', '')
            result["error"] = f"AWS SDK Client Error - Error Code: {error_code}, Error Message: {error_msg}, Error: " + str(e)
            if error_code == 'ResourceNotFoundException':
                result["not_found"] = True
        except Exception as e:
            result["error"] = str(e)

        return result

    def _set_secret_aws(self, client, key: str, value: str):
        """Write AWS secret using the provided client and secret key and value"""
        result = {
            "success": False,
            "not_found": False,
            "error": None
        }

        exists = False
        dst_value = None
        try:
            get_secret_value_response = client.get_secret_value(SecretId=key)
            if ('SecretString' in get_secret_value_response or 'SecretBinary' in get_secret_value_response):
                exists = True
            if 'SecretString' in get_secret_value_response:
                dst_value = get_secret_value_response['SecretString']
            elif 'SecretBinary' in get_secret_value_response:
                dst_value = base64.b64decode(get_secret_value_response['SecretBinary'])
        except Exception:
            pass

        try:
            # create fails on existing secret, and put fails on non-existent
            if exists:
                if value != dst_value:
                    client.put_secret_value(SecretId=key, SecretString=value)
            else:
                client.create_secret(Name=key, SecretString=value)
            result["success"] = True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = e.response.get('Error', {}).get('Message', '')
            result["error"] = f"AWS SDK Client Error - Error Code: {error_code}, Error Message: {error_msg}, Error: " + str(e)
            if error_code == 'ResourceNotFoundException':
                result["not_found"] = True
        except Exception as e:
            result["error"] = str(e)

        return result


DEFAULT_AWS_KEY_NAME = "ksm-config"


class AwsSecretStorage(KeyValueStorage):
    """AWS Secrets Manager secret as a config storage"""

    def __init__(self, aws_key: str = "", fallback_to_default_profile: bool = True):
        """Initilaizes AwsSecretStorage with provider using ec2instance config.

        AwsSecretStorage by default uses Ec2Instance config with
        fallback to default session set to True. To switch to a different
        configuration method use one of its helper methods.
        """

        if not aws_key:
            aws_key = os.getenv("KSM_AWS_SECRET", DEFAULT_AWS_KEY_NAME)

        self.provider = AwsConfigProvider(aws_key)
        self.provider.from_ec2instance_config(aws_key, fallback_to_default_profile)

        self.config = {}
        self.last_saved_config_hash = ""
        # self.__load_config()  # don't initialize here - use helpers

    def from_default_config(self, aws_key: str, fallback_to_default_profile: bool = True):
        self.provider = AwsConfigProvider(aws_key)
        self.provider.from_default_config(aws_key, fallback_to_default_profile)
        self.config = {}
        self.last_saved_config_hash = ""
        self.__load_config()

    def from_profile_config(self, aws_key: str, profile: str, fallback_to_default_profile: bool = True):
        self.provider = AwsConfigProvider(aws_key)
        self.provider.from_profile_config(aws_key, profile, fallback_to_default_profile)
        self.config = {}
        self.last_saved_config_hash = ""
        self.__load_config()

    def from_ec2instance_config(self, aws_key: str, fallback_to_default_profile: bool = True):
        self.provider = AwsConfigProvider(aws_key)
        self.provider.from_ec2instance_config(aws_key, fallback_to_default_profile)
        self.config = {}
        self.last_saved_config_hash = ""
        self.__load_config()

    def from_custom_config(self, aws_key: str,
                           aws_access_key_id: str,
                           aws_secret_access_key: str,
                           region: str,
                           fallback_to_default_profile: bool = True):
        self.provider.from_custom_config(
            aws_key,
            aws_access_key_id,
            aws_secret_access_key,
            region,
            fallback_to_default_profile)
        self.config = {}
        self.last_saved_config_hash = ""
        self.__load_config()

    # low level hepler methods to do actual read/write
    def __load_config(self):
        err = ""
        try:
            contents = self.provider.read_config()
            if len(contents) == 0:
                logger.warning(f"Empty config from AWS secret '{self.provider.key_name}'")

            config = None
            if is_base64(contents):
                contents = url_safe_str_to_bytes(contents)
            if is_json(contents):
                config = json.loads(contents)

            # AWS secret should be plaintext, but if it is JSON
            # we must make sure it is (valid) KSM JSON - check for privateKey
            if config and config.get("privateKey", ""):
                self.config = config
                self.last_saved_config_hash = hashlib.md5(json.dumps(config, indent=4, sort_keys=True).encode()).hexdigest()
            else:
                err = f"Failed to load/parse config JSON from AWS secret '{self.provider.key_name}' - the value must be a valid JSON, value='{contents}'"
        except Exception as e:
            logger.error(f"Failed to load config JSON from AWS secret '{self.provider.key_name}', Error: {str(e)}")

        if err:
            raise ValueError(err)

    def __save_config(self, updated_config: dict = {}, module=0, force=False):
        config = self.config if self.config else {}
        config_json: str = json.dumps(config, indent=4, sort_keys=True)
        config_hash = hashlib.md5(config_json.encode()).hexdigest()

        if updated_config:
            ucfg_json: str = json.dumps(updated_config, indent=4, sort_keys=True)
            ucfg_hash = hashlib.md5(ucfg_json.encode()).hexdigest()
            if ucfg_hash != config_hash:
                config_hash = ucfg_hash
                config_json = ucfg_json
                self.config = dict(updated_config)
                # update after save - to allow for retries
                # self.last_saved_config_hash = config_hash

        if not force and config_hash == self.last_saved_config_hash:
            logger.warning("Skipped config JSON save. No changes detected.")
            return

        # self.create_config_if_missing() # secret must exist in AWS
        self.provider.write_config(config_json)
        self.last_saved_config_hash = config_hash

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
