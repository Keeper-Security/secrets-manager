# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import base64
import enum
import json
import logging
from colorama import Fore, Style
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.keeper_globals import logger_name


# Labels are case sensitive
# Use Hidden Field fields in custom section of the record

AZURE_KEYVAULT_NAME_LABEL = "Azure Key Vault Name"
AZURE_TENANT_ID_LABEL = "Azure Tenant ID"
AZURE_CLIENT_ID_LABEL = "Azure Client ID"
AZURE_CLIENT_SECRET_LABEL = "Azure Client Secret"

AWS_ACCESS_KEY_ID_LABEL = "AWS Access Key ID"
AWS_SECRET_ACCESS_KEY_LABEL = "AWS Secret Access Key"
AWS_REGION_NAME_LABEL = "AWS Region Name"


class Sync:
    def __init__(self, cli):
        self.cli = cli
        self.logger = logging.getLogger(logger_name)

        # Since the cli is short lived, this won't stick around long.
        self.local_cache = {}

    def _get_secret(self, notation):
        # If not in the cache, go get the secret and then store it in the cache.
        if notation not in self.local_cache:
            value = self.cli.client.get_notation(notation)
            if type(value) is dict or type(value) is list:
                value = json.dumps(value)
            self.local_cache[notation] = str(value) if (value is not None) else None

        return self.local_cache[notation]

    def _get_secret_field(self, record, field, silent=True):
        value = None
        try:
            value = record.get_standard_field_value(field, True)
        except:
            pass
        if not value:
            try:
                value = record.get_custom_field_value(field, True)
            except:
                pass

        if not value and not silent:
            raise KsmCliException(f"Cannot find '{field}' field for UID {record.uid}.")

        return value

    def _get_secret_az(self, client, key):
        from azure.core.exceptions import (
            ClientAuthenticationError,
            HttpResponseError,
            ServiceRequestError,
            ResourceNotFoundError,
            AzureError
        )

        result = {
            "value": None,
            "not_found": False,
            "error": None
        }

        try:
            result["value"] = client.get_secret(key)
        except ClientAuthenticationError as e:
            # Can occur if either tenant_id, client_id or client_secret is incorrect
            print("Azure SDK was not able to connect to Key Vault. Skipping key=" + str(key), e)
            result["error"] = str(e)
        except ResourceNotFoundError:
            # Deleted or non existing key during get_secret.
            # Note: ResourceNotFoundError is HttpResponseError so check NotFound first
            result["not_found"] = True
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            print("Azure SDK HttpResponseError - Possible wrong Vault name given", e)
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            print("Azure SDK Network error", e)
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            print("Azure SDK error", e)
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)
        return result

    def _set_secret_az(self, client, key:str, value:str):
        from azure.core.exceptions import (
            ClientAuthenticationError,
            HttpResponseError,
            ServiceRequestError,
            ResourceExistsError,
            ResourceNotFoundError,
            AzureError
        )

        result = {
            "success": False,
            "restored": False,
            "purged": False,
            "error": None
        }

        try:
            secret = client.set_secret(key, value)
            if secret.value == value:
                result["success"] = True
            else:
                result["error"] = f"set secret succeeded but values don't match - '{key}': {secret.value} != {value}"
        except ClientAuthenticationError as e:
            # Can occur if either tenant_id, client_id or client_secret is incorrect
            print("Azure SDK was not able to connect to Key Vault. Skipping key=" + str(key), e)
            result["error"] = str(e)
        except ResourceNotFoundError as e:
            # Deleted or non existing key during get_secret.
            # Note: ResourceNotFoundError is HttpResponseError so check ResourceNotFound first
            result["error"] = str(e)
        except ResourceExistsError as e:
            # Deleted key with soft-delete enabled during set_secret.
            # Note: ResourceExistsError is HttpResponseError so check ResourceExists first
            try:
                client.begin_recover_deleted_secret(key).wait()
                result["restored"] = True
            except Exception as re:
                result["error"] = f" secret --name '{key}' was deleted and failed to restore. " + str(re)
                try:
                    # client.begin_delete_secret(secretName).wait()
                    client.purge_deleted_secret(key)
                    result["purged"] = True
                except Exception as pe:
                    result["error"] += f" secret --name '{key}' was deleted and failed to purge. " + str(pe)
            # retry on successful restore/purge
            if result.get("restored", False) or result.get("purged", False):
                try:
                    secret = client.set_secret(key, value)
                    if secret.value == value:
                        result["success"] = True
                    else:
                        result["error"] = f"set secret succeeded but values don't match - '{key}': {secret.value} != {value}"
                except Exception as e:
                    result["error"] += f" Retry attempt failed to set new value for secret --name '{key}'. " \
                        f" You may have to manually inspect and delete the secret if it exists in the vault. " \
                        " Error: " + str(e)
            else:
                result["error"] += f" Failed to restore/purge deleted secret '{key}' and cannot set to a new value."
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            print("Azure SDK HttpResponseError - Possible wrong Vault name given", e)
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            print("Azure SDK Network error", e)
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            print("Azure SDK error", e)
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)
        return result

    def _delete_secret_az(self, client, key):
        from azure.core.exceptions import (
            ClientAuthenticationError,
            HttpResponseError,
            ServiceRequestError,
            ResourceNotFoundError,
            AzureError
        )

        result = {
            "success": False,
            "error": None
        }

        try:
            secret = client.begin_delete_secret(key).wait()
            # client.purge_deleted_secret(secretName)
            result["success"] = True
        except ClientAuthenticationError as e:
            # Can occur if either tenant_id, client_id or client_secret is incorrect
            print("Azure SDK was not able to connect to Key Vault. Skipping key=" + str(key), e)
            result["error"] = str(e)
        except ResourceNotFoundError as e:
            # Deleted or non existing key during get_secret.
            # Note: ResourceNotFoundError is HttpResponseError so check NotFound first
            result["success"] = True # already deleted
            result["error"] = str(e)
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            print("Azure SDK HttpResponseError - Possible wrong Vault name given", e)
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            print("Azure SDK Network error", e)
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            print("Azure SDK error", e)
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)
        return result

    def _get_secret_aws(self, client, key):
        from botocore.exceptions import ClientError

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
            if error_code == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                print("AWS SDK was unable decrypt the value. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                print("AWS SDK detected an error on server side. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                print("AWS SDK detected an invalid value for a parameter. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                print("AWS SDK detected a parameter value that is not valid for the current state of the resource. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource. Deleted or non existing key during get_secret_value.
                result["not_found"] = True
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                print("AWS SDK detected that the security token included in the request is invalid. Skipping key=" + str(key), e)
                result["error"] = str(e)
            else:
                # Unknown client error
                print("AWS SDK detected unknown client error. Skipping key=" + str(key), e)
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)

        return result

    def _set_secret_aws(self, client, key:str, value:str):
        from botocore.exceptions import ClientError

        result = {
            "success": False,
            "not_found": False,
            "restored": False,
            "purged": False,
            "error": None
        }

        exists = False
        dst_value = None
        try:
            get_secret_value_response = client.get_secret_value(SecretId=key)
            if ('SecretString' in get_secret_value_response or
                'SecretBinary' in get_secret_value_response):
                exists = True
            if 'SecretString' in get_secret_value_response:
                dst_value = get_secret_value_response['SecretString']
            elif 'SecretBinary' in get_secret_value_response:
                dst_value = base64.b64decode(get_secret_value_response['SecretBinary'])
        except:
            pass

        try:
            # create fails on existing secret, and put fails on non-existent
            if exists:
                if value != dst_value:
                    response = client.put_secret_value(SecretId=key, SecretString=value)
                else:
                    print("New value is the same as old value. Skipping key=" + str(key))
            else:
                response = client.create_secret(Name=key, SecretString=value)
            result["success"] = True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                print("AWS SDK was unable decrypt the value. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                print("AWS SDK detected an error on server side. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                print("AWS SDK detected an invalid value for a parameter. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                http_code = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode', -1)
                err_msg = e.response.get('Error', {}).get('Message', '')
                if http_code == 400 and err_msg.endswith('scheduled for deletion.'):
                    # "You can't create this secret because a secret with this name is already scheduled for deletion."
                    # probably delete_secret(SecretId=key, RecoveryWindowInDays=30)
                    try:
                        res = client.restore_secret(SecretId=key)
                        result["restored"] = True
                    except Exception as re:
                        result["error"] = f" secret --name '{key}' was deleted and failed to restore. " + str(re)
                        try:
                            res = client.delete_secret(SecretId=key, ForceDeleteWithoutRecovery=True)
                            result["purged"] = True
                        except Exception as pe:
                            result["error"] += f" secret --name '{key}' was deleted and failed to purge. " + str(pe)
                    # retry on successful restore/purge
                    if result.get("restored", False):
                        try:
                            response = client.put_secret_value(SecretId=key, SecretString=value)
                            result["success"] = True
                        except Exception as e:
                            result["error"] += f" Retry attempt failed to set new value for secret --name '{key}'. " \
                                f" You may have to manually inspect and delete the secret if it exists in the vault. " \
                                " Error: " + str(e)
                    elif result.get("purged", False):
                        try:
                            response = client.create_secret(Name=key, SecretString=value)
                            result["success"] = True
                        except Exception as e:
                            result["error"] += f" Retry attempt failed to set new value for secret --name '{key}'. " \
                                f" You may have to manually inspect and delete the secret if it exists in the vault. " \
                                " Error: " + str(e)
                    else:
                        result["error"] += f" Failed to restore/purge deleted secret '{key}' and cannot set to a new value."
                else:
                    print("AWS SDK detected a parameter value that is not valid for the current state of the resource. Skipping key=" + str(key), e)
                    result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource. Deleted or non existing key during get_secret_value.
                result["not_found"] = True
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                print("AWS SDK detected that the security token included in the request is invalid. Skipping key=" + str(key), e)
                result["error"] = str(e)
            else:
                # Unknown client error
                print("AWS SDK detected unknown client error. Skipping key=" + str(key), e)
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)
        return result

    def _delete_secret_aws(self, client, key):
        from botocore.exceptions import ClientError

        result = {
            "success": False,
            "error": None
        }

        try:
            res = client.delete_secret(SecretId=key, RecoveryWindowInDays=30)
            # res = client.delete_secret(SecretId=key, ForceDeleteWithoutRecovery=True)
            result["success"] = True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                print("AWS SDK was unable decrypt the value. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                print("AWS SDK detected an error on server side. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                print("AWS SDK detected an invalid value for a parameter. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                print("AWS SDK detected a parameter value that is not valid for the current state of the resource. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource. Deleted or non existing key during get_secret_value.
                print("AWS SDK can't find the resource. Skipping key=" + str(key), e)
                result["error"] = str(e)
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                print("AWS SDK detected that the security token included in the request is invalid. Skipping key=" + str(key), e)
                result["error"] = str(e)
            else:
                # Unknown client error
                print("AWS SDK detected unknown client error. Skipping key=" + str(key), e)
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            print("Unknown error", e)
            result["error"] = str(e)
        return result

    def sync_values(self, type:str, credentials:str=None, dry_run=False, dont_delete=False, map=None):

        map = map or []
        result = []

        """
        stats = {
            "totalMappings": 0,
            "badMappings": [], # bad notation
            "duplicateKeys": {}, # errors
            "duplicateKeyValuePairs": {}, # warnings
            "uniqueRecords": set(), # parsed from --map options
            "missingRecords": set(), # missing in keeper vault
        }

        keys = set()
        kvps = set()
        rxuid = r"^(?:keeper:\/\/)(?P<uid>[0-9a-zA-Z\-_]{22})\/"
        for m in map:
            stats["totalMappings"] = stats.get("totalMappings", 0) + 1
            if not isinstance(m, tuple) or len(m) != 2:
                stats["badMappings"].append(m)
            else:
                if m in kvps:
                    stats["duplicateKeyValuePairs"][m] = stats["duplicateKeyValuePairs"].get(m, 1) + 1
                elif m[0] in keys:
                    stats["duplicateKeys"][m[0]] = stats["duplicateKeys"].get(m[0], 1) + 1
                keys.add(m[0])
                kvps.add(m)

                matches = re.search(rxuid, m[1])
                if matches and matches.group("uid"):
                    stats["uniqueRecords"].add(matches.group("uid"))
                else:
                    stats["badMappings"].append(m)

        print("Total Mappings:\t" + str(stats.get("totalMappings", 0)), file = sys.stderr ) # warning if 0
        print("Bad Mappings:\t" + str(len(stats.get("badMappings", []))), file = sys.stderr ) # error if > 0
        print("Duplicate Keys:\t" + str(len(stats.get("duplicateKeys", {}))), file = sys.stderr ) # error if > 0
        print("Duplicate Key Value Pairs:\t" + str(len(stats.get("duplicateKeyValuePairs", {}))), file = sys.stderr ) # warning if > 0
        print("Unique Records:\t" + str(len(stats.get("uniqueRecords", set()))), file = sys.stderr ) # warning if 0
        print("Missing Records:\t" + str(len(stats.get("missingRecords", set()))), file = sys.stderr ) # warning/error if > 0
        """

        for m in map:
            try:
                value = self._get_secret(m[1])
                result.append({"mapKey": m[0], "mapNotation": m[1], "srcValue": value})
            except Exception as err:
                result.append({"mapKey": m[0], "mapNotation": m[1], "srcValue": None})
                # errstr = str(err)
                # if errstr.startswith("Could not find a record with the UID "):
                #     stats["missingRecords"].add(errstr.split(' ')[-1])

        if type == 'json':
            self.cli.output(json.dumps(result, indent=4))
        elif type == 'azure':
            self.sync_azure(credentials, dry_run, dont_delete, result)
        elif type == 'aws':
            self.sync_aws(credentials, dry_run, dont_delete, result)
        else:
            raise KsmCliException(f"Invalid option `--type {type}`. Allowed values are (json, azure, aws).")

    def sync_azure(self, credentials:str=None, dry_run=False, dont_delete=False, map:dict=None):
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import ClientSecretCredential
        except ImportError as ie:
            print(Fore.RED + "Missing Azure dependencies. To install missing packages run: \r\n" +
                Fore.YELLOW + "pip3 install azure-identity azure-keyvault-secrets\r\n" + Style.RESET_ALL)
            raise KsmCliException("Missing Azure Dependencies: " + str(ie))

        if not map or len(map) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL)
            return

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL)
            return

        credentials = str(credentials).strip()
        secrets = self.cli.client.get_secrets(uids=[credentials])
        if len(secrets) == 0:
            raise KsmCliException("Cannot find the record with Azure credentials " + credentials)
        creds = secrets[0]

        # NB! Labels are case sensitive. Use Hidden Field fields in custom section of the record.
        vault_name = self._get_secret_field(creds, AZURE_KEYVAULT_NAME_LABEL)
        tenant_id = self._get_secret_field(creds, AZURE_TENANT_ID_LABEL)
        client_id = self._get_secret_field(creds, AZURE_CLIENT_ID_LABEL)
        client_secret = self._get_secret_field(creds, AZURE_CLIENT_SECRET_LABEL)

        if not vault_name:
            print(Fore.YELLOW + "Missing Vault Name in credentials record " + credentials + Style.RESET_ALL)
        if not tenant_id:
            print(Fore.YELLOW + "Missing Tenant Id in credentials record " + credentials + Style.RESET_ALL)
        if not client_id:
            print(Fore.YELLOW + "Missing Client Id in credentials record " + credentials + Style.RESET_ALL)
        if not client_secret:
            print(Fore.YELLOW + "Missing Client Secret in credentials record " + credentials + Style.RESET_ALL)
        if not(vault_name and tenant_id and client_id and client_secret):
            raise KsmCliException(f"Cannot find all required credentials in record UID {credentials}.")

        vault_url = f"https://{vault_name}.vault.azure.net"
        az_credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret)
        client = SecretClient(vault_url=vault_url, credential=az_credential)

        if dry_run:
            for m in map:
                key = m["mapKey"]
                res = self._get_secret_az(client, key)
                val = res.get("value", None)
                m["dstValue"] = val.value if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    print("Error reading the value from Azure Vault for key=" + key +" - " + res.get("error", ""))
            self.cli.output(json.dumps(map, indent=4))
        else:
            for m in map:
                key = m["mapKey"]
                val = m["srcValue"]
                if val is None:
                    if dont_delete:
                        continue
                    else:
                        res = self._delete_secret_az(client, key)
                        if res.get("error", ""):
                            print("Error deleting key=" + key + " - " + res.get("error", ""))
                else:
                    res = self._set_secret_az(client, key, val)
                    if res.get("error", ""):
                        print("Error setting new value for key=" + key + " - " + res.get("error", ""))


    def sync_aws(self, credentials:str=None, dry_run=False, dont_delete=False, map:dict=None):
        try:
            import boto3
        except ImportError as ie:
            print(Fore.RED + "Missing AWS dependencies. Install missing packages with: \r\n" +
                Fore.YELLOW + "pip3 install boto3\r\n" + Style.RESET_ALL)
            raise KsmCliException("Missing AWS Dependencies: " + str(ie))

        if not map or len(map) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL)
            return

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL)
            return

        credentials = str(credentials).strip()
        secrets = self.cli.client.get_secrets(uids=[credentials])
        if len(secrets) == 0:
            raise KsmCliException("Cannot find the record with AWS credentials " + credentials)
        creds = secrets[0]

        # NB! Labels are case sensitive. Use Hidden Field fields in custom section of the record.
        aws_access_key_id = self._get_secret_field(creds, AWS_ACCESS_KEY_ID_LABEL)
        aws_secret_access_key = self._get_secret_field(creds, AWS_SECRET_ACCESS_KEY_LABEL)
        aws_region_name = self._get_secret_field(creds, AWS_REGION_NAME_LABEL)

        if not aws_access_key_id:
            print(Fore.YELLOW + "Missing AWS Access Key in credentials record " + credentials + Style.RESET_ALL)
        if not aws_secret_access_key:
            print(Fore.YELLOW + "Missing AWS Secret Access Key in credentials record " + credentials + Style.RESET_ALL)
        if not aws_region_name:
            print(Fore.YELLOW + "Missing AWS Region Name in credentials record " + credentials + Style.RESET_ALL)
        if not(aws_access_key_id and aws_secret_access_key and aws_region_name):
            raise KsmCliException(f"Cannot find all required credentials in record UID {credentials}.")

        secretsmanager = boto3.client('secretsmanager',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region_name
        )

        if dry_run:
            for m in map:
                key = m["mapKey"]
                res = self._get_secret_aws(secretsmanager, key)
                val = res.get("value", None)
                m["dstValue"] = val.value if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    print("Error reading the value from AWS Secrets Manager for key=" + key +" - " + res.get("error", ""))
            self.cli.output(json.dumps(map, indent=4))
        else:
            for m in map:
                key = m["mapKey"]
                val = m["srcValue"]
                if val is None:
                    if dont_delete:
                        continue
                    else:
                        res = self._delete_secret_aws(secretsmanager, key)
                        if res.get("error", ""):
                            print("Error deleting key=" + key + " - " + res.get("error", ""))
                else:
                    res = self._set_secret_aws(secretsmanager, key, val)
                    if res.get("error", ""):
                        print("Error setting new value for key=" + key + " - " + res.get("error", ""))
