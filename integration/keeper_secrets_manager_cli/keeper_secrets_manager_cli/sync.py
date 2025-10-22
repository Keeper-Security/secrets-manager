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
import json
import logging
import re
import sys
import urllib.parse
from colorama import Fore, Style
from keeper_secrets_manager_cli.exception import KsmCliException
from keeper_secrets_manager_core.keeper_globals import logger_name


# Use Hidden Field fields in custom section of the record
# Labels are case sensitive
AZURE_KEYVAULT_NAME_LABEL = "Azure Key Vault Name"
AZURE_TENANT_ID_LABEL = "Azure Tenant ID"
AZURE_CLIENT_ID_LABEL = "Azure Client ID"
AZURE_CLIENT_SECRET_LABEL = "Azure Client Secret"

AWS_ACCESS_KEY_ID_LABEL = "AWS Access Key ID"
AWS_SECRET_ACCESS_KEY_LABEL = "AWS Secret Access Key"
AWS_REGION_NAME_LABEL = "AWS Region Name"

GOOGLE_CLOUD_PROJECT_ID_LABEL = "Google Cloud Project ID"
GOOGLE_APPLICATION_CREDENTIALS_LABEL = "Google Application Credentials" # If missing use default creds (ADC)


class Sync:
    def __init__(self, cli):
        self.cli = cli
        self.logger = logging.getLogger(logger_name)
        self.log = []

        # Since the cli is short lived, this won't stick around long.
        self.local_cache = {}

    def _output(self, data: list, hide_data:bool=False):
        data = data or []
        failed = sum(1 for x in data if x.get("error", "") != "")
        output = {
            "data": data,
            "log": self.log,
            "status": {
                "processed": len(data),
                "failed": failed
            }
        }
        if hide_data:
            del output["data"]
        self.cli.output(json.dumps(output, indent=2))

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
            # # Can occur if either tenant_id, client_id or client_secret is incorrect
            # self.log.append(f"Azure SDK was not able to connect to Key Vault. {e.message} Skipping key={key}")
            # self.logger.error("Azure SDK was not able to connect to Key Vault. " + str(e))
            # result["error"] = str(e)
            raise KsmCliException(f"Azure SDK was not able to connect to Key Vault. Check your credentials. Message: {e.message}")
        except ResourceNotFoundError as e:
            # Deleted or non existing key.
            # Note: ResourceNotFoundError is HttpResponseError so check NotFound first
            self.logger.debug(f"Azure SDK: resource not found. key={key} Message: {e.message}")
            result["not_found"] = True
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            self.log.append(f"Azure SDK HttpResponseError - Possible wrong Vault name given. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK HttpResponseError - Possible wrong Vault name given. " + str(e))
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            self.log.append(f"Azure SDK Network error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK Network error. " + str(e))
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            self.log.append(f"Azure SDK error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK error. " + str(e))
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
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
                msg = f"set secret succeeded but values don't match - '{key}': {secret.value} != {value}"
                self.log.append(msg)
                self.logger.error(msg)
                result["error"] = msg
        except ClientAuthenticationError as e:
            # # Can occur if either tenant_id, client_id or client_secret is incorrect
            # self.log.append(f"Azure SDK was not able to connect to Key Vault. {e.message} Skipping key={key}")
            # self.logger.error("Azure SDK was not able to connect to Key Vault. " + str(e))
            # result["error"] = str(e)
            raise KsmCliException(f"Azure SDK was not able to connect to Key Vault. Check your credentials. Message: {e.message}")
        except ResourceNotFoundError as e:
            # Deleted keys with soft-delete enabled produce ResourceExistsError
            # Note: ResourceNotFoundError is HttpResponseError so check ResourceNotFound first
            self.log.append(f"Azure SDK: Resource not found. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK: Resource not found. " + str(e))
            result["error"] = str(e)
        except ResourceExistsError as e:
            # Deleted key with soft-delete enabled.
            # Note: ResourceExistsError is HttpResponseError so check ResourceExists first
            try:
                client.begin_recover_deleted_secret(key).wait()
                result["restored"] = True
            except Exception as re:
                # try to recover: restore failed try to purge instead
                # result["error"] = f" secret --name '{key}' was deleted and failed to restore. " + str(re)
                self.logger.debug(f" secret --name '{key}' was deleted and failed to restore. " + str(re))
                try:
                    # client.begin_delete_secret(secretName).wait()
                    client.purge_deleted_secret(key)
                    result["purged"] = True
                except Exception as pe:
                    msg = f" secret --name '{key}' was deleted and failed to purge. " + str(pe)
                    self.logger.error(msg)
                    result["error"] += msg
            # retry on successful restore/purge
            if result.get("restored", False) or result.get("purged", False):
                try:
                    secret = client.set_secret(key, value)
                    if secret.value == value:
                        result["success"] = True
                    else:
                        msg = f"set secret succeeded but values don't match - '{key}': {secret.value} != {value}"
                        self.logger.error(msg)
                        result["error"] = msg
                except Exception as e:
                    msg = f" Retry attempt failed to set new value for secret --name '{key}'. " \
                        " You may have to manually inspect and delete the secret if it exists in the vault. " \
                        " Error: " + str(e)
                    self.logger.error(msg)
                    result["error"] += msg
            else:
                self.logger.error(f"Failed to restore/purge deleted secret '{key}' and cannot set to a new value.")
                result["error"] += f" Failed to restore/purge deleted secret '{key}' and cannot set to a new value."
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            self.log.append(f"Azure SDK HttpResponseError - Possible wrong Vault name given. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK HttpResponseError - Possible wrong Vault name given. " + str(e))
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            self.log.append(f"Azure SDK Network error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK Network error. " + str(e))
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            self.log.append(f"Azure SDK error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK error. " + str(e))
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
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
            # # Can occur if either tenant_id, client_id or client_secret is incorrect
            # self.log.append(f"Azure SDK was not able to connect to Key Vault. {e.message} Skipping key={key}")
            # self.logger.error("Azure SDK was not able to connect to Key Vault. " + str(e))
            # result["error"] = str(e)
            raise KsmCliException(f"Azure SDK was not able to connect to Key Vault. Check your credentials. Message: {e.message}")
        except ResourceNotFoundError as e:
            # Deleted or non existing key.
            # Note: ResourceNotFoundError is HttpResponseError so check NotFound first
            self.logger.debug(f"Azure SDK ResourceNotFoundError while trying to delete secret. key={key} already deleted. Message: {e.message}")
            result["success"] = True # already deleted
            result["error"] = str(e)
        except HttpResponseError as e:
            # One reason is when Key Vault Name is incorrect
            self.log.append(f"Azure SDK HttpResponseError - Possible wrong Vault name given. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK HttpResponseError - Possible wrong Vault name given. " + str(e))
            result["error"] = str(e)
        except ServiceRequestError as e:
            # Network error
            self.log.append(f"Azure SDK Network error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK Network error. " + str(e))
            result["error"] = str(e)
        except AzureError as e:
            # Will catch everything that is from Azure SDK, but not the two previous
            self.log.append(f"Azure SDK error. {e.message} Skipping key={key}")
            self.logger.error("Azure SDK error. " + str(e))
            result["error"] = str(e)
        except Exception as e:
            # Anything else that is not Azure related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
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
            error_msg  = e.response.get('Error', {}).get('Message', '')
            if error_code == 'InvalidSignatureException':
                # # Can occur if credentials are incorrect or expired
                # self.log.append(f"AWS SDK was not able to connect to Secrets Manager. {error_msg} Skipping key={key}")
                # self.logger.error("AWS SDK was not able to connect to Secrets Manager. " + str(e))
                # result["error"] = str(e)
                raise KsmCliException(f"AWS SDK was not able to connect to Secrets Manager. Check your credentials. Message: {error_msg}")
            elif error_code == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                self.log.append(f"AWS SDK: decryption failure. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: decryption failure. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                self.log.append(f"AWS SDK: an error occurred on the server side. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: an error occurred on the server side. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                self.log.append(f"AWS SDK: provided an invalid value for a parameter. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: provided an invalid value for a parameter. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                self.log.append(f"AWS SDK: provided parameter value that is not valid for the current state of the resource. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: provided parameter value that is not valid for the current state of the resource. " + str(e))
                result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource. Deleted or non existing key.
                self.logger.debug(f"AWS SDK: resource not found. key={key}")
                result["not_found"] = True
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                self.log.append(f"AWS SDK: security token included in the request is invalid. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: security token included in the request is invalid. " + str(e))
                result["error"] = str(e)
            else:
                # Unknown client error
                self.log.append(f"AWS SDK: unknown client error. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: unknown client error. " + str(e))
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
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
                    self.logger.warning(f"New value is the same as old value. Skipping key={key}")
            else:
                response = client.create_secret(Name=key, SecretString=value)
            result["success"] = True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg  = e.response.get('Error', {}).get('Message', '')
            if error_code == 'InvalidSignatureException':
                # # Can occur if credentials are incorrect or expired
                # self.log.append(f"AWS SDK was not able to connect to Secrets Manager. {error_msg} Skipping key={key}")
                # self.logger.error("AWS SDK was not able to connect to Secrets Manager. " + str(e))
                # result["error"] = str(e)
                raise KsmCliException(f"AWS SDK was not able to connect to Secrets Manager. Check your credentials. Message: {error_msg}")
            elif error_code == 'LimitExceededException':
                # API request quota exceeded, Secrets Manager throttles the request
                self.log.append(f"AWS SDK: request quota exceeded - throttled. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: request quota exceeded - throttled. " + str(e))
                result["error"] = str(e)
            elif error_code == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                self.log.append(f"AWS SDK: decryption failure. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: decryption failure. " + str(e))
                result["error"] = str(e)
            elif error_code == 'EncryptionFailure':
                self.log.append(f"AWS SDK: encryption failure. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: encryption failure. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                self.log.append(f"AWS SDK: an error occurred on the server side. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: an error occurred on the server side. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                self.log.append(f"AWS SDK: provided an invalid value for a parameter. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: provided an invalid value for a parameter. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                http_code = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode', -1)
                err_msg = e.response.get('Error', {}).get('Message', '')
                if http_code == 400 and err_msg.endswith('scheduled for deletion.'):
                    # "You can't create this secret because a secret with this name is already scheduled for deletion."
                    # ex. delete_secret(SecretId=key, RecoveryWindowInDays=30)
                    try:
                        res = client.restore_secret(SecretId=key)
                        result["restored"] = True
                    except Exception as re:
                        # try to recover: restore failed try to purge instead
                        # result["error"] = f" secret --name '{key}' was deleted and failed to restore. " + str(re)
                        self.logger.debug(f" secret --name '{key}' was deleted and failed to restore. " + str(re))
                        try:
                            res = client.delete_secret(SecretId=key, ForceDeleteWithoutRecovery=True)
                            result["purged"] = True
                        except Exception as pe:
                            self.logger.error(f" secret --name '{key}' was deleted and failed to purge. " + str(pe))
                            result["error"] += f" secret --name '{key}' was deleted and failed to purge. " + str(pe)
                    # retry on successful restore/purge
                    if result.get("restored", False):
                        try:
                            response = client.put_secret_value(SecretId=key, SecretString=value)
                            result["success"] = True
                        except Exception as e:
                            msg = f" Retry attempt failed to set new value for secret --name '{key}'. " \
                                " You may have to manually inspect and delete the secret if it exists in the vault. " \
                                " Error: " + str(e)
                            self.logger.error(msg)
                            result["error"] += msg
                    elif result.get("purged", False):
                        try:
                            response = client.create_secret(Name=key, SecretString=value)
                            result["success"] = True
                        except Exception as e:
                            msg = f" Retry attempt failed to set new value for secret --name '{key}'. " \
                                f" You may have to manually inspect and delete the secret if it exists in the vault. " \
                                " Error:  " + str(e)
                            self.logger.error(msg)
                            result["error"] += msg
                    else:
                        self.logger.error(f"Failed to restore/purge deleted secret '{key}' and cannot set to a new value.")
                        result["error"] += f" Failed to restore/purge deleted secret '{key}' and cannot set to a new value."
                else:
                    self.log.append(f"AWS SDK: a parameter value is not valid for the current state of the resource. {error_msg} Skipping key={key}")
                    self.logger.error("AWS SDK: a parameter value is not valid for the current state of the resource. " + str(e))
                    result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource.
                self.log.append(f"AWS SDK: resource not found. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: resource not found. " + str(e))
                result["not_found"] = True
                result["error"] = str(e)
            elif error_code == 'ResourceExistsException':
                self.log.append(f"AWS SDK: resource exists. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: resource exists. " + str(e))
                result["error"] = str(e)
            elif error_code == 'MalformedPolicyDocumentException':
                self.log.append(f"AWS SDK: malformed policy document. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: malformed policy document. " + str(e))
                result["error"] = str(e)
            elif error_code == 'PreconditionNotMetException':
                self.log.append(f"AWS SDK: precondition not met. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: precondition not met. " + str(e))
                result["error"] = str(e)
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                self.log.append(f"AWS SDK: security token included in the request is invalid. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: security token included in the request is invalid. " + str(e))
                result["error"] = str(e)
            else:
                # Unknown client error
                self.log.append(f"AWS SDK: unknown client error. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: unknown client error. " + str(e))
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
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
            error_msg  = e.response.get('Error', {}).get('Message', '')
            if error_code == 'InvalidSignatureException':
                # # Can occur if credentials are incorrect or expired
                # self.log.append(f"AWS SDK was not able to connect to Secrets Manager. {error_msg} Skipping key={key}")
                # self.logger.error("AWS SDK was not able to connect to Secrets Manager. " + str(e))
                # result["error"] = str(e)
                raise KsmCliException(f"AWS SDK was not able to connect to Secrets Manager. Check your credentials. Message: {error_msg}")
            elif error_code == 'InternalServiceErrorException':
                # An error occurred on the server side.
                self.log.append(f"AWS SDK: an error occurred on the server side. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: an error occurred on the server side. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                self.log.append(f"AWS SDK: provided an invalid value for a parameter. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: provided an invalid value for a parameter. " + str(e))
                result["error"] = str(e)
            elif error_code == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                self.log.append(f"AWS SDK: provided parameter value that is not valid for the current state of the resource. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: provided parameter value that is not valid for the current state of the resource. " + str(e))
                result["error"] = str(e)
            elif error_code == 'ResourceNotFoundException':
                # Can't find the resource. Deleted or non existing key.
                self.logger.debug(f"AWS SDK: ResourceNotFoundException while trying to delete secret. key={key} already deleted. Message: {error_msg}")
                result["success"] = True # already deleted
                result["error"] = str(e)
            elif error_code == 'UnrecognizedClientException':
                # The security token included in the request is invalid.
                self.log.append(f"AWS SDK: security token included in the request is invalid. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: security token included in the request is invalid. " + str(e))
                result["error"] = str(e)
            else:
                # Unknown client error
                self.log.append(f"AWS SDK: unknown client error. {error_msg} Skipping key={key}")
                self.logger.error("AWS SDK: unknown client error. " + str(e))
                result["error"] = str(e)
        except Exception as e:
            # Anything else that is not AWS related (network, stdlib, etc.)
            self.log.append(f"Unknown error. Skipping key={key}")
            self.logger.error("Unknown error. " + str(e))
            result["error"] = str(e)
        return result

    def _get_secret_gcp(self, client, project_id, secret_id):
        from google.api_core.exceptions import (
            ClientError,
            GoogleAPIError,
            NotFound,
            ServerError
        )

        result = {
            "value": None,
            "not_found": False,
            "error": None
        }

        try:
            version_id="latest"
            name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
            secret = client.access_secret_version(request={"name": name})
            result["value"] = secret.payload.data.decode("UTF-8")
            # crc32c = google_crc32c.Checksum()
            # crc32c.update(secret.payload.data)
            # if secret.payload.data_crc32c != int(crc32c.hexdigest(), 16):
            #     result["error"] =  f"Data corruption detected for key={secret_id}"
        except NotFound as e:
            # Deleted or non existing key.
            self.logger.debug(f"GCP Client: secret not found. key={secret_id} Message: {e.message}")
            result["not_found"] = True
        except ClientError as e:
            # Includes - PermissionDenied, Forbidden, Unauthenticated, Unauthorized
            self.log.append(f"GCP SDK Client error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Client error. " + str(e))
            result["error"] = str(e)
        except ServerError as e:
            self.log.append(f"GCP SDK Server error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Server error. " + str(e))
            result["error"] = str(e)
        except GoogleAPIError as e:
            # Will catch everything that is from GCP SDK
            self.log.append(f"GCP API error. {str(e)} Skipping key={secret_id}")
            self.logger.error("GCP API error. " + str(e))
            result["error"] = str(e)
        except Exception as e:
            self.log.append(f"Error retrieving secret. Skipping key={secret_id}")
            self.logger.error("Error retrieving secret. " + str(e))
            result["error"] = str(e)
        return result

    def _set_secret_gcp(self, client, project_id:str, secret_id:str, value:str):
        from google.api_core.exceptions import (
            AlreadyExists,
            ClientError,
            GoogleAPIError,
            NotFound,
            ServerError
        )

        result = {
            "success": False,
            "error": None
        }

        existing_value = None
        try:
            version_id="latest"
            name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
            secret = client.access_secret_version(request={"name": name})
            existing_value = secret.payload.data.decode("UTF-8")
        except Exception:
            pass

        # avoid creating new versions with the same value
        if existing_value == value:
            result["success"] = True
            return result

        err = ""
        if existing_value is None: # key doesn't exist - create
            try:
                parent = f"projects/{project_id}"
                secret = client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
                if not(secret and secret.create_time):
                    err = f"Failed to create secret {secret_id} "
            except AlreadyExists as e:
                pass
            except Exception as e:
                err = f"Failed to create secret {secret_id} - Error: {str(e)}"

        try:
            parent = client.secret_path(project_id, secret_id)
            response = client.add_secret_version(request={"parent": parent, "payload": {"data": value.encode("UTF-8")}})
            if response and response.create_time:
                result["success"] = True
        except NotFound as e:
            # Deleted or non existing key.
            self.logger.debug(f"GCP Client: secret not found. key={secret_id} Message: {e.message}")
            result["error"] = "Key not found. Error: " + err + str(e)
        except ClientError as e:
            # Includes - PermissionDenied, Forbidden, Unauthenticated, Unauthorized
            self.log.append(f"GCP SDK Client error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Client error. " + str(e))
            result["error"] = err + str(e)
        except ServerError as e:
            self.log.append(f"GCP SDK Server error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Server error. " + str(e))
            result["error"] = err + str(e)
        except GoogleAPIError as e:
            # Will catch everything that is from GCP SDK
            self.log.append(f"GCP API error. {str(e)} Skipping key={secret_id}")
            self.logger.error("GCP API error. " + str(e))
            result["error"] = err + str(e)
        except Exception as e:
            self.log.append(f"Unknown error. Skipping key={secret_id}")
            self.logger.error("Unknown error. " + str(e) + " : " + err)
            result["error"] = err + str(e)
        return result

    def _delete_secret_gcp(self, client, project_id:str, secret_id:str):
        from google.api_core.exceptions import (
            ClientError,
            GoogleAPIError,
            NotFound,
            ServerError
        )

        result = {
            "success": False,
            "error": None
        }

        try:
            # Delete the secret with the given name and all of its versions.
            name = client.secret_path(project_id, secret_id)
            client.delete_secret(request={"name": name})
            result["success"] = True
        except NotFound as e:
            # Deleted or non existing key.
            self.logger.debug(f"GCP Client Error: NotFound while trying to delete secret. key={secret_id} already deleted. Message: {e.message}")
            result["success"] = True # already deleted
            result["error"] = str(e)
        except ClientError as e:
            # Includes - PermissionDenied, Forbidden, Unauthenticated, Unauthorized
            self.log.append(f"GCP SDK Client error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Client error. " + str(e))
            result["error"] = str(e)
        except ServerError as e:
            self.log.append(f"GCP SDK Server error. {e.message} Skipping key={secret_id}")
            self.logger.error("GCP SDK Server error. " + str(e))
            result["error"] = str(e)
        except GoogleAPIError as e:
            # Will catch everything that is from GCP SDK
            self.log.append(f"GCP API error. {str(e)} Skipping key={secret_id}")
            self.logger.error("GCP API error. " + str(e))
            result["error"] = str(e)
        except Exception as e:
            self.log.append(f"Error deleting secret. Skipped delete key={secret_id}")
            self.logger.error("Error deleting secret. " + str(e))
            result["error"] = str(e)
        return result

    def _validate_aws_secret_name(self, name):
        """Validate AWS secret name and return (converted_name, error_message)"""
        errors = []
        name = name.replace(' ', '_')  # spaces not allowed in a secret name

        # AWS: Secret name must contain only alphanumeric characters and the characters /_+=.@-
        allowed_pattern = r'^[A-Za-z0-9/_+=.@\-]+$'
        if not re.match(allowed_pattern, name):
            invalid_chars = set(re.sub(r'[A-Za-z0-9/_+=.@\-]', '', name))
            errors.append(f"contains invalid characters: {', '.join(repr(c) for c in sorted(invalid_chars))}")

        # Check for ARN suffix behavior
        # if secret name ends with hyphen + 6 chars, it may cause AWS confusion
        if re.match(r'.*-[A-Za-z0-9]{6}$', name):
            print(Fore.YELLOW + f"Warning: KMS Secret name '{name}' ends with hyphen + 6 chars - may cause ARN confusion" + Style.RESET_ALL, file=sys.stderr)

        # Check length (1-512 characters)
        if not(1 <= len(name) <= 512):
            errors.append("AWS secret name must be between 1 and 512 character long")

        # Return converted name and aggregated error message
        error_msg = "; ".join(errors) if errors else None
        return name, error_msg

    def _resolve_records(self, record_tokens):
        """Resolve record tokens to actual records"""
        if not record_tokens:
            return []

        # Remove duplicates and warn
        unique_tokens = list(dict.fromkeys(record_tokens))  # Preserves order, removes duplicates
        if len(unique_tokens) != len(record_tokens):
            duplicates = [token for token in record_tokens if record_tokens.count(token) > 1]
            unique_duplicates = list(set(duplicates))
            self.log.append(f"Duplicate records found and removed: {unique_duplicates}")
            print(Fore.YELLOW + f"Warning: Duplicate records found and removed: {unique_duplicates}" + Style.RESET_ALL, file=sys.stderr)

        # Get all secrets to resolve by UID or title
        all_secrets = self.cli.client.get_secrets()

        # Remove any duplicates - these are linked records/shortcuts
        seen_uids = set()
        unique_secrets = []  # Keep only unique UIDs
        for secret in all_secrets:
            if secret.uid not in seen_uids:
                seen_uids.add(secret.uid)
                unique_secrets.append(secret)

        all_secrets = unique_secrets

        resolved_records = []
        resolution_errors = []
        for token in unique_tokens:
            matches = []
            for secret in all_secrets:
                if secret.uid == token or secret.title == token:
                    matches.append(secret)

            if len(matches) == 0:
                resolution_errors.append(f"No record found matching token: '{token}'")
            elif len(matches) > 1:
                match_info = [f"{m.title} (UID: {m.uid})" for m in matches]
                resolution_errors.append(f"Multiple records found matching '{token}': {match_info}")
            else:
                resolved_records.append(matches[0])

        if resolution_errors:
            error_message = "Record resolution errors:\n"
            for error in resolution_errors:
                error_message += f"  - {error}\n"
            raise KsmCliException(error_message.rstrip())

        # Check and remove duplicate UIDs after resolving
        # ex. record://UID, record://Title may resolve to same UID
        uids = [record.uid for record in resolved_records]
        unique_uids = list(dict.fromkeys(uids))
        if len(unique_uids) != len(uids):
            duplicate_uids = [uid for uid in unique_uids if uids.count(uid) > 1]
            self.log.append(f"Duplicate UIDs found in resolved records - removed duplicates: {duplicate_uids}")
            print(Fore.YELLOW + f"Warning: Duplicate UIDs found in resolved records - removed duplicates: {duplicate_uids}" + Style.RESET_ALL, file=sys.stderr)
            # Remove duplicates
            seen = set()
            resolved_records = [record for record in resolved_records if not (record.uid in seen or seen.add(record.uid))]

        return resolved_records

    def _build_folder_path(self, folder, all_folders):
        """Build full path for a folder using folder_uid and parent_uid"""
        # Build a map of folder_uid -> folder for quick lookup
        folder_map = {f.folder_uid: f for f in all_folders}

        # Build path from bottom to top
        path_parts = []
        current = folder
        visited = set()

        while current:
            # Add current folder name
            folder_name = current.name if hasattr(current, 'name') else current.folder_uid
            path_parts.insert(0, folder_name)

            # Check for circular reference
            if current.folder_uid in visited:
                break
            visited.add(current.folder_uid)

            # Move to parent (parent_uid == "" means root folder)
            if hasattr(current, 'parent_uid') and current.parent_uid and current.parent_uid != "":
                current = folder_map.get(current.parent_uid)
            else:
                break

        return "/".join(path_parts)

    def _parse_path_token(self, token):
        """Parse path token, handling // as escaped / (not a delimiter)"""
        # Replace // with a placeholder
        placeholder = "\x00"  # Use null character as placeholder
        escaped = token.replace("//", placeholder)

        # Split by /
        parts = escaped.split("/")

        # Restore // in each part
        parts = [part.replace(placeholder, "/") for part in parts]

        return parts

    def _resolve_folders(self, folder_tokens, recursive=False):
        """Resolve folder tokens to folder objects (not records)"""
        if not folder_tokens:
            return []

        # UID regex pattern
        uid_pattern = r'^[0-9a-zA-Z\-_]{22}$'

        # Remove duplicates and warn
        unique_tokens = list(dict.fromkeys(folder_tokens))
        if len(unique_tokens) != len(folder_tokens):
            duplicates = [token for token in folder_tokens if folder_tokens.count(token) > 1]
            unique_duplicates = list(set(duplicates))
            self.log.append(f"Duplicate folder tokens found and removed: {unique_duplicates}")
            print(Fore.YELLOW + f"Warning: Duplicate folder tokens found and removed: {unique_duplicates}" + Style.RESET_ALL, file=sys.stderr)

        # Get all folders from the client
        try:
            all_folders = self.cli.client.get_folders()
        except Exception as e:
            raise KsmCliException(f"Failed to retrieve folders: {str(e)}")

        resolved_folders = []
        resolution_errors = []

        for token in unique_tokens:
            matches = []

            # 1. Try to match by UID (exact regex match)
            if re.match(uid_pattern, token):
                for folder in all_folders:
                    if folder.folder_uid == token:
                        matches.append(folder)

            # 2. If no UID match, try by path
            if not matches:
                # Parse the token path (handle // as escaped /)
                token_parts = self._parse_path_token(token)

                # Build paths for all folders and compare
                for folder in all_folders:
                    folder_path = self._build_folder_path(folder, all_folders)
                    folder_parts = self._parse_path_token(folder_path)

                    # Check if token_parts match anywhere in the folder tree
                    # Match can be: exact match or token_parts is a suffix of folder_parts
                    if folder_parts == token_parts:
                        matches.append(folder)
                    elif len(token_parts) <= len(folder_parts):
                        # Check if token_parts match the end of folder_parts
                        if folder_parts[-len(token_parts):] == token_parts:
                            matches.append(folder)

            # 3. If no path match, try by title (name only)
            if not matches:
                for folder in all_folders:
                    if hasattr(folder, 'name') and folder.name == token:
                        matches.append(folder)

            if len(matches) == 0:
                resolution_errors.append(f"No folder found matching token: '{token}'")
            elif len(matches) > 1:
                match_info = []
                for m in matches:
                    name = m.name if hasattr(m, 'name') else 'Unknown'
                    path = self._build_folder_path(m, all_folders)
                    match_info.append(f"{name} (UID: {m.folder_uid}, Path: {path})")
                resolution_errors.append(f"Multiple folders found matching '{token}': {match_info}")
            else:
                resolved_folders.append(matches[0])

        if resolution_errors:
            error_message = "Folder resolution errors:\n"
            for error in resolution_errors:
                error_message += f"  - {error}\n"
            raise KsmCliException(error_message.rstrip())

        # Check for duplicate folder UIDs
        folder_uids = [folder.folder_uid for folder in resolved_folders]
        unique_folder_uids = list(dict.fromkeys(folder_uids))
        if len(unique_folder_uids) != len(folder_uids):
            duplicate_uids = [uid for uid in unique_folder_uids if folder_uids.count(uid) > 1]
            self.log.append(f"Duplicate folder UIDs found - removed duplicates: {duplicate_uids}")
            print(Fore.YELLOW + f"Warning: Duplicate folder UIDs found - removed duplicates: {duplicate_uids}" + Style.RESET_ALL, file=sys.stderr)
            # Remove duplicates
            seen = set()
            resolved_folders = [folder for folder in resolved_folders if not (folder.folder_uid in seen or seen.add(folder.folder_uid))]

        return resolved_folders

    def _stringify(self, value):
        """Convert a value to string for AWS Secrets Manager compatibility"""
        if not isinstance(value, str):
            return json.dumps(value, separators=(',', ':'))
        return value  # Return string as-is, no quotes

    def _generate_record_json(self, record, raw_json=False):
        """Generate JSON content from a record"""
        if raw_json:
            # Return full JSON (same as: secret get UID --json)
            return record.dict
        else:
            # Generate flattened JSON with only fields.type=value and custom.label=value
            # AWS Secrets Manager KVP defaults to string:string format
            flattened = {}
            duplicate_keys = []

            def add_to_flattened(key, value):
                """Add key-value to flattened dict, handling duplicates with suffixes"""
                if key in flattened:
                    duplicate_keys.append(key)
                    counter = 2
                    new_key = f"{key}:{counter}"
                    while new_key in flattened:
                        counter += 1
                        new_key = f"{key}:{counter}"
                    key = new_key
                flattened[key] = value

            # Get record data as dict
            record_dict = record.dict if hasattr(record, 'dict') else {}

            # Process standard fields from record.dict.get('fields', [])
            fields = record_dict.get('fields', [])
            for field in fields:
                if isinstance(field, dict):
                    field_type = field.get('type')
                    field_value = field.get('value')

                    # Skip if no type or value is None/empty
                    if not field_type or field_value is None:
                        continue

                    # Skip empty values
                    if field_value == "" or field_value == []:
                        continue

                    # Handle list values
                    if isinstance(field_value, list):
                        if len(field_value) == 0:
                            continue
                        elif len(field_value) == 1:
                            # Single element: convert to string
                            add_to_flattened(field_type, str(field_value[0]))
                        else:
                            # Multiple elements: JSON stringify
                            add_to_flattened(field_type, json.dumps(field_value, separators=(',', ':')))
                    else:
                        # Non-list value: convert to string
                        add_to_flattened(field_type, str(field_value))

            # Process custom fields from record.dict.get('custom', [])
            custom_fields = record_dict.get('custom', [])
            for custom_field in custom_fields:
                if isinstance(custom_field, dict):
                    field_label = custom_field.get('label')
                    field_value = custom_field.get('value')

                    # Skip if no label or value is None/empty
                    if not field_label or field_value is None:
                        continue

                    # Skip empty values
                    if field_value == "" or field_value == []:
                        continue

                    # Handle list values
                    if isinstance(field_value, list):
                        if len(field_value) == 0:
                            continue
                        elif len(field_value) == 1:
                            # Single element: convert to string
                            add_to_flattened(field_label, str(field_value[0]))
                        else:
                            # Multiple elements: JSON stringify
                            add_to_flattened(field_label, json.dumps(field_value, separators=(',', ':')))
                    else:
                        # Non-list value: convert to string
                        add_to_flattened(field_label, str(field_value))

            # Warn about duplicate keys if any
            if duplicate_keys:
                unique_duplicates = list(set(duplicate_keys))
                record_title = record.title if hasattr(record, 'title') else 'Unknown'
                self.log.append(f"Duplicate keys found in record '{record_title}': {unique_duplicates} - added suffixes")
                print(Fore.YELLOW + f"Warning: Duplicate keys found in record '{record_title}': {unique_duplicates} - added suffixes (:2, :3, etc.)" + Style.RESET_ALL, file=sys.stderr)

            # Return the dictionary (not JSON string) for AWS JSON format
            return flattened

    def _validate_aws_map_keys(self, maps):
        """Validate AWS map keys for duplicates and format conflicts. Returns True if using JSON format."""
        # Step 1: Validate AWS secret names and collect validated keys
        validation_errors = []
        validated_maps = []  # List of (original_key, validated_kms_key, json_key_or_none, notation)

        for m in maps:
            original_key = m[0]
            notation = m[1]

            if '+' in original_key:
                # New format: kms_key+json_key
                kms_key, json_key = original_key.split('+', 1)

                # Validate the KMS key part
                validated_kms_key, error_msg = self._validate_aws_secret_name(kms_key)
                if error_msg:
                    validation_errors.append(f"KMS key '{kms_key}' in '{original_key}': {error_msg}")

                validated_maps.append((original_key, validated_kms_key, json_key, notation))
            else:
                # Old format: plain key
                validated_key, error_msg = self._validate_aws_secret_name(original_key)
                if error_msg:
                    validation_errors.append(f"Key '{original_key}': {error_msg}")

                validated_maps.append((original_key, validated_key, None, notation))

        # If there are validation errors, display them all at once
        if validation_errors:
            error_message = "AWS KMS secret name validation errors (from --map):\n"
            for error in validation_errors:
                error_message += f"  - {error}\n"
            raise KsmCliException(error_message.rstrip())

        # Step 2: Check for duplicates AFTER validation/conversion
        # Collect validated KMS keys from both formats
        json_format_kms_keys = set()  # Validated KMS keys from new format (kms_key+json_key)
        plain_format_keys = set()     # Validated keys from old format (plain key)

        # Track keys for duplicate detection
        kms_json_keys = {}  # For JSON format: {validated_kms_key: [(json_key, original_key)]}
        plain_key_info = {}  # For plain format: {validated_key: [(original_key, notation)]}

        for original_key, validated_kms_key, json_key, notation in validated_maps:
            if json_key is not None:
                # JSON format
                json_format_kms_keys.add(validated_kms_key)

                if validated_kms_key not in kms_json_keys:
                    kms_json_keys[validated_kms_key] = []
                kms_json_keys[validated_kms_key].append((json_key, original_key))
            else:
                # Plain format
                plain_format_keys.add(validated_kms_key)

                if validated_kms_key not in plain_key_info:
                    plain_key_info[validated_kms_key] = []
                plain_key_info[validated_kms_key].append((original_key, notation))

        # Collect all duplicate issues
        error_messages = []

        # Check for duplicate plain keys (after validation)
        duplicate_plain_keys = []
        for validated_key, info_list in plain_key_info.items():
            if len(info_list) > 1:
                original_keys = [orig for orig, _ in info_list]
                if len(set(original_keys)) > 1:
                    # Different original keys map to same validated key
                    keys_str = ', '.join(f"'{k}'" for k in original_keys)
                    duplicate_plain_keys.append(f"AWS secret name '{validated_key}' maps to multiple --map entries: {keys_str}")
                else:
                    # Same key appears multiple times
                    duplicate_plain_keys.append(f"'{original_keys[0]}' appears {len(info_list)} times")

        if duplicate_plain_keys:
            error_messages.append("Duplicate plain keys:\n    " + "\n    ".join(duplicate_plain_keys))

        # Check for duplicate JSON keys within same KMS key
        duplicate_json_keys = []
        for validated_kms_key, json_key_list in kms_json_keys.items():
            seen = {}  # json_key -> original_key
            for json_key, original_key in json_key_list:
                if json_key in seen:
                    duplicate_json_keys.append(f"KMS key '{validated_kms_key}': duplicate JSON key '{json_key}' in '{seen[json_key]}' and '{original_key}'")
                seen[json_key] = original_key

        if duplicate_json_keys:
            error_messages.append("Duplicate JSON keys within same KMS key:\n    " + "\n    ".join(duplicate_json_keys))

        # Check for overlapping KMS keys between formats (after validation)
        overlapping = json_format_kms_keys & plain_format_keys
        if overlapping:
            overlapping_details = []
            for validated_key in sorted(overlapping):
                # Get original keys from both formats
                plain_originals = [orig for orig, _ in plain_key_info.get(validated_key, [])]
                json_originals = [orig for _, orig in kms_json_keys.get(validated_key, [])]

                plain_str = ', '.join(f"'{k}'" for k in plain_originals)
                json_str = ', '.join(f"'{k}'" for k in json_originals)
                overlapping_details.append(f"AWS secret name '{validated_key}' used in both plain format ({plain_str}) and JSON format ({json_str})")

            error_messages.append("Cannot use both plain and JSON format for the same AWS secret name:\n    " + "\n    ".join(overlapping_details))

        # Raise exception with all duplicate issues
        if error_messages:
            raise KsmCliException("Duplicate keys found (from --map):\n  " + "\n  ".join(error_messages))

        # Return True if we have JSON format keys
        return bool(json_format_kms_keys)

    def _process_aws_records_and_folders(self, result, records, folders, folders_recursive, raw_json, maps):
        """Process AWS-specific --record, --folder, and --folder-recursive options and update result list"""
        # Handle record option for AWS
        if records:
            resolved_records = self._resolve_records(records)

            # Collect validation errors and validated secret names
            validation_errors = []
            validated_records = []  # List of (record_obj, secret_name)

            for record_obj in resolved_records:
                # Validate record title for AWS compatibility
                secret_name, error_msg = self._validate_aws_secret_name(record_obj.title)

                if error_msg:
                    validation_errors.append(f"'{record_obj.title}' (UID: {record_obj.uid}): {error_msg}")

                validated_records.append((record_obj, secret_name))

            # If there are validation errors, display them all at once
            if validation_errors:
                error_message = "AWS KMS secret name validation errors:\n"
                for error in validation_errors:
                    error_message += f"  - {error}\n"
                raise KsmCliException(error_message.rstrip())

            # Check for duplicate AWS secret names AFTER validation/conversion
            secret_names = [secret_name for _, secret_name in validated_records]
            seen_names = {}
            duplicates = []

            for record_obj, secret_name in validated_records:
                if secret_name in seen_names:
                    # Found duplicate
                    first_record = seen_names[secret_name]
                    duplicates.append(f"AWS secret name '{secret_name}' maps to multiple records: '{first_record.title}' (UID: {first_record.uid}) and '{record_obj.title}' (UID: {record_obj.uid})")
                else:
                    seen_names[secret_name] = record_obj

            if duplicates:
                error_message = "Duplicate AWS secret names after conversion:\n"
                for dup in duplicates:
                    error_message += f"  - {dup}\n"
                raise KsmCliException(error_message.rstrip())

            # Now add to result (no duplicates at this point)
            for record_obj, secret_name in validated_records:
                # Generate JSON content from record
                json_content = self._generate_record_json(record_obj, raw_json)

                # Add to result
                result.append({
                    "mapKey": secret_name,
                    "mapNotation": f"record:{record_obj.uid}",
                    "srcValue": json_content,
                    "dstValue": None
                })

            # Check for duplicate keys between --map and --record
            if maps:
                # Extract KMS key part (before '+' for JSON format, or full key for plain format)
                map_keys = []
                for m in maps:
                    key = m[0]
                    if '+' in key:
                        # JSON format: extract KMS key part (before '+')
                        kms_key = key.split('+', 1)[0]
                        # Validate and convert it
                        validated_kms_key, _ = self._validate_aws_secret_name(kms_key)
                        map_keys.append(validated_kms_key)
                    else:
                        # Plain format: validate and convert full key
                        validated_key, _ = self._validate_aws_secret_name(key)
                        map_keys.append(validated_key)

                record_keys = [secret_name for _, secret_name in validated_records]
                overlapping = set(map_keys) & set(record_keys)
                if overlapping:
                    raise KsmCliException(f"Duplicate keys found between --map and --record: {', '.join(overlapping)}")

        # Handle folder and folder-recursive options for AWS
        # First, resolve all folders before getting records
        resolved_folders = []
        resolved_folders_recursive = []

        if folders:
            resolved_folders = self._resolve_folders(folders, recursive=False)

        if folders_recursive:
            resolved_folders_recursive = self._resolve_folders(folders_recursive, recursive=True)

        # 1. Check for duplicate UIDs between --folder and --folder-recursive
        if resolved_folders and resolved_folders_recursive:
            folder_uids = set(f.folder_uid for f in resolved_folders)
            folder_recursive_uids = set(f.folder_uid for f in resolved_folders_recursive)
            duplicate_uids = folder_uids & folder_recursive_uids

            if duplicate_uids:
                duplicate_names = []
                for folder in resolved_folders + resolved_folders_recursive:
                    if folder.folder_uid in duplicate_uids:
                        name = folder.name if hasattr(folder, 'name') else folder.folder_uid
                        duplicate_names.append(f"{name} (UID: {folder.folder_uid})")
                raise KsmCliException(f"Same folder(s) specified in both --folder and --folder-recursive: {', '.join(set(duplicate_names))}")

        # 2. Check for overlapping folders (recursive within recursive, folder within recursive)
        all_folders_for_overlap_check = []
        if resolved_folders:
            all_folders_for_overlap_check.extend([(f, False) for f in resolved_folders])
        if resolved_folders_recursive:
            all_folders_for_overlap_check.extend([(f, True) for f in resolved_folders_recursive])

        # Only check for overlaps if we have folders to check
        if all_folders_for_overlap_check:
            # Get all folders to check parent-child relationships
            try:
                all_available_folders = self.cli.client.get_folders()
            except Exception:
                all_available_folders = []

            # Build parent-child map
            folder_parent_map = {}  # {folder_uid: parent_uid}
            for folder in all_available_folders:
                if hasattr(folder, 'parent_uid') and folder.parent_uid:
                    folder_parent_map[folder.folder_uid] = folder.parent_uid

            def is_ancestor(potential_ancestor_uid, child_uid):
                """Check if potential_ancestor_uid is an ancestor of child_uid"""
                current = child_uid
                visited = set()
                while current in folder_parent_map:
                    if current in visited:  # Circular reference protection
                        break
                    visited.add(current)
                    parent = folder_parent_map[current]
                    if parent == potential_ancestor_uid:
                        return True
                    current = parent
                return False

            # Find overlaps
            overlaps_to_remove = []
            overlap_warnings = []

            for i, (folder1, is_recursive1) in enumerate(all_folders_for_overlap_check):
                for j, (folder2, is_recursive2) in enumerate(all_folders_for_overlap_check):
                    if i >= j:  # Skip self and already compared pairs
                        continue

                    folder1_name = folder1.name if hasattr(folder1, 'name') else folder1.folder_uid
                    folder2_name = folder2.name if hasattr(folder2, 'name') else folder2.folder_uid

                    # Case 1: Both recursive - check if one is ancestor of the other
                    if is_recursive1 and is_recursive2:
                        if is_ancestor(folder1.folder_uid, folder2.folder_uid):
                            overlap_warnings.append(f"Recursive folder '{folder2_name}' is within recursive folder '{folder1_name}' - will skip '{folder2_name}'")
                            overlaps_to_remove.append(folder2.folder_uid)
                        elif is_ancestor(folder2.folder_uid, folder1.folder_uid):
                            overlap_warnings.append(f"Recursive folder '{folder1_name}' is within recursive folder '{folder2_name}' - will skip '{folder1_name}'")
                            overlaps_to_remove.append(folder1.folder_uid)

                    # Case 2: Non-recursive folder within recursive folder
                    elif not is_recursive1 and is_recursive2:
                        if is_ancestor(folder2.folder_uid, folder1.folder_uid) or folder1.folder_uid == folder2.folder_uid:
                            overlap_warnings.append(f"Folder '{folder1_name}' is within recursive folder '{folder2_name}' - will skip '{folder1_name}'")
                            overlaps_to_remove.append(folder1.folder_uid)
                    elif is_recursive1 and not is_recursive2:
                        if is_ancestor(folder1.folder_uid, folder2.folder_uid) or folder1.folder_uid == folder2.folder_uid:
                            overlap_warnings.append(f"Folder '{folder2_name}' is within recursive folder '{folder1_name}' - will skip '{folder2_name}'")
                            overlaps_to_remove.append(folder2.folder_uid)

            # Print overlap warnings and remove duplicates
            if overlap_warnings:
                unique_warnings = list(set(overlap_warnings))
                for warning in unique_warnings:
                    self.log.append(warning)
                    print(Fore.YELLOW + f"Warning: {warning}" + Style.RESET_ALL, file=sys.stderr)

            # Remove overlapping folders
            overlaps_to_remove = set(overlaps_to_remove)
            resolved_folders = [f for f in resolved_folders if f.folder_uid not in overlaps_to_remove]
            resolved_folders_recursive = [f for f in resolved_folders_recursive if f.folder_uid not in overlaps_to_remove]

        # Now get records from resolved folders
        folder_records_with_metadata = []  # Initialize before try block

        if resolved_folders or resolved_folders_recursive:
            try:
                # Get full response with folder structure and records
                full_response = self.cli.client.get_secrets(full_response=True)

                # Step 1: Build folder tree using get_folders() output
                all_folders = self.cli.client.get_folders()
                folder_tree = {}  # folder_uid -> {records: [], children: [], parent_uid: None}

                for folder in all_folders:
                    folder_uid = folder.folder_uid if hasattr(folder, 'folder_uid') else None
                    if not folder_uid:
                        continue

                    # Initialize folder entry
                    folder_tree[folder_uid] = {'records': [], 'children': [], 'parent_uid': None}

                    # Store parent_uid for building tree
                    if hasattr(folder, 'parent_uid'):
                        folder_tree[folder_uid]['parent_uid'] = folder.parent_uid

                # Build parent-child relationships
                for folder_uid, folder_info in folder_tree.items():
                    parent_uid = folder_info.get('parent_uid')
                    if parent_uid and parent_uid != '' and parent_uid in folder_tree:
                        folder_tree[parent_uid]['children'].append(folder_uid)

                # Step 2: Populate folder tree with records from full_response.records
                if hasattr(full_response, 'records') and full_response.records:
                    for record in full_response.records:
                        if not hasattr(record, 'uid'):
                            continue

                        # Determine which folder the record belongs to
                        # Priority: inner_folder_uid > folder_uid > directly shared (no folder)
                        record_folder_uid = None

                        if hasattr(record, 'inner_folder_uid') and record.inner_folder_uid and record.inner_folder_uid != '':
                            record_folder_uid = record.inner_folder_uid
                        elif hasattr(record, 'folder_uid') and record.folder_uid and record.folder_uid != '':
                            record_folder_uid = record.folder_uid
                        # else: record is directly shared to KSM App (no folder)

                        # Add record to the appropriate folder
                        if record_folder_uid and record_folder_uid in folder_tree:
                            folder_tree[record_folder_uid]['records'].append(record)

                # Helper function to get all records from a folder (recursive)
                def get_records_recursive(folder_uid, visited=None):
                    if visited is None:
                        visited = set()

                    if folder_uid in visited or folder_uid not in folder_tree:
                        return []

                    visited.add(folder_uid)
                    records = list(folder_tree[folder_uid]['records'])

                    # Get records from child folders
                    for child_uid in folder_tree[folder_uid].get('children', []):
                        records.extend(get_records_recursive(child_uid, visited))

                    return records

                # Helper function to get records from a folder (non-recursive)
                def get_records_non_recursive(folder_uid):
                    if folder_uid not in folder_tree:
                        return []
                    return list(folder_tree[folder_uid]['records'])

                # Collect records from resolved folders with metadata
                # Track: (record, folder_uid, is_recursive)

                # Collect records from resolved folders (non-recursive)
                for folder in resolved_folders:
                    folder_recs = get_records_non_recursive(folder.folder_uid)
                    for rec in folder_recs:
                        folder_records_with_metadata.append((rec, folder.folder_uid, False))

                # Collect records from resolved folders (recursive)
                for folder in resolved_folders_recursive:
                    folder_recs = get_records_recursive(folder.folder_uid)
                    for rec in folder_recs:
                        folder_records_with_metadata.append((rec, folder.folder_uid, True))

            except Exception as e:
                self.log.append(f"Warning: Failed to retrieve records from folders: {str(e)}")
                print(Fore.YELLOW + f"Warning: Failed to retrieve records from folders: {str(e)}" + Style.RESET_ALL, file=sys.stderr)

        # Remove duplicate records by UID (keep first occurrence with its metadata)
        seen_folder_record_uids = set()
        unique_folder_records_with_metadata = []
        for rec_tuple in folder_records_with_metadata:
            record, folder_uid, is_recursive = rec_tuple
            if record.uid not in seen_folder_record_uids:
                seen_folder_record_uids.add(record.uid)
                unique_folder_records_with_metadata.append(rec_tuple)

        if len(unique_folder_records_with_metadata) != len(folder_records_with_metadata):
            removed_count = len(folder_records_with_metadata) - len(unique_folder_records_with_metadata)
            self.log.append(f"Removed {removed_count} duplicate records from folder results")

        # Check for overlap with --record option
        if records and unique_folder_records_with_metadata:
            # Get UIDs from resolved records
            record_uids = set(r.uid for r in resolved_records) if records else set()
            folder_record_uids = set(rec_tuple[0].uid for rec_tuple in unique_folder_records_with_metadata)
            overlapping_record_uids = record_uids & folder_record_uids

            if overlapping_record_uids:
                overlap_details = []
                for uid in overlapping_record_uids:
                    # Find the record title
                    for rec_tuple in unique_folder_records_with_metadata:
                        record, _, _ = rec_tuple
                        if record.uid == uid:
                            title = record.title if hasattr(record, 'title') else uid
                            overlap_details.append(f"'{title}' (UID: {uid})")
                            break

                warning_msg = f"Records found in both --record and --folder/--folder-recursive: {', '.join(overlap_details)} - will keep only one copy"
                self.log.append(warning_msg)
                print(Fore.YELLOW + f"Warning: {warning_msg}" + Style.RESET_ALL, file=sys.stderr)

        # Process folder records
        if unique_folder_records_with_metadata:
            # Collect validation errors and validated folder records
            validation_errors = []
            validated_folder_records = []  # List of (record_obj, secret_name, source_folder_uid, is_recursive)

            for rec_tuple in unique_folder_records_with_metadata:
                record_obj, source_folder_uid, is_recursive = rec_tuple

                # Validate record title for AWS compatibility
                secret_name, error_msg = self._validate_aws_secret_name(record_obj.title)

                if error_msg:
                    folder_type = "-fr" if is_recursive else "-f"
                    validation_errors.append(f"'{record_obj.title}' (UID: {record_obj.uid}) from {folder_type} {source_folder_uid}: {error_msg}")

                validated_folder_records.append((record_obj, secret_name, source_folder_uid, is_recursive))

            # If there are validation errors, display them all at once
            if validation_errors:
                error_message = "AWS KMS secret name validation errors (from --folder/--folder-recursive):\n"
                for error in validation_errors:
                    error_message += f"  - {error}\n"
                raise KsmCliException(error_message.rstrip())

            # Check for duplicate AWS secret names AFTER validation/conversion (within folder records)
            folder_secret_names = [secret_name for _, secret_name, _, _ in validated_folder_records]
            seen_folder_names = {}
            folder_duplicates = []

            for record_obj, secret_name, source_folder_uid, is_recursive in validated_folder_records:
                if secret_name in seen_folder_names:
                    # Found duplicate
                    first_record, first_folder_uid, first_is_recursive = seen_folder_names[secret_name]
                    first_folder_type = "-fr" if first_is_recursive else "-f"
                    current_folder_type = "-fr" if is_recursive else "-f"
                    folder_duplicates.append(f"AWS secret name '{secret_name}' maps to multiple records: '{first_record.title}' (UID: {first_record.uid}) from {first_folder_type} {first_folder_uid} and '{record_obj.title}' (UID: {record_obj.uid}) from {current_folder_type} {source_folder_uid}")
                else:
                    seen_folder_names[secret_name] = (record_obj, source_folder_uid, is_recursive)

            if folder_duplicates:
                error_message = "Duplicate AWS secret names after conversion (from --folder/--folder-recursive):\n"
                for dup in folder_duplicates:
                    error_message += f"  - {dup}\n"
                raise KsmCliException(error_message.rstrip())

            # Now add to result (no duplicates within folder records at this point)
            for record_obj, secret_name, source_folder_uid, is_recursive in validated_folder_records:
                # Generate JSON content from record
                json_content = self._generate_record_json(record_obj, raw_json)

                # Add to result with correct mapNotation
                map_notation_prefix = "folder-recursive" if is_recursive else "folder"
                result.append({
                    "mapKey": secret_name,
                    "mapNotation": f"{map_notation_prefix}:{record_obj.uid}",
                    "srcValue": json_content,
                    "dstValue": None
                })

            # Check for duplicate keys between existing entries and folder records
            if maps or records:
                # Extract AWS secret names from existing entries (handling JSON format)
                existing_keys = []
                for r in result:
                    if r.get("mapNotation", "").startswith("folder:") or r.get("mapNotation", "").startswith("folder-recursive:"):
                        continue

                    map_key = r["mapKey"]
                    if '+' in map_key:
                        # JSON format: extract KMS key part (before '+')
                        kms_key = map_key.split('+', 1)[0]
                        # Validate and convert it
                        validated_kms_key, _ = self._validate_aws_secret_name(kms_key)
                        existing_keys.append(validated_kms_key)
                    else:
                        # Plain format or already validated record key
                        existing_keys.append(map_key)

                folder_keys = [secret_name for _, secret_name, _, _ in validated_folder_records]
                overlapping = set(existing_keys) & set(folder_keys)
                if overlapping:
                    raise KsmCliException(f"Duplicate keys found between --map/--record and --folder/--folder-recursive: {', '.join(overlapping)}")

    def sync_values(self, sync_type:str, credentials:str="", dry_run=False, preserve_missing=False, maps=None, records=None, folders=None, folders_recursive=None, raw_json=False):
        maps = maps or []
        result = []

        # Validate AWS map keys early (for type=aws and type=json)
        # Both GCP/Azure don't allow + in key names so
        # --map kms_key+json_key keeper://notation is AWS JSON key format
        if (sync_type == 'aws' or sync_type == 'json') and maps:
            self._validate_aws_map_keys(maps)

        r"""
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
        for m in maps:
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

        for m in maps:
            try:
                value = self._get_secret(m[1])
                result.append({"mapKey": m[0], "mapNotation": m[1], "srcValue": value, "dstValue": None})
            except Exception as err:
                item = {"mapKey": m[0], "mapNotation": m[1], "srcValue": None, "dstValue": None}
                errstr = str(err)
                if errstr.startswith("Could not find a record with the UID "):
                    # stats["missingRecords"].add(errstr.split(' ')[-1])
                    item["error"] = "Error reading the value from Keeper Vault - Could not find a record with the UID."
                    self.log.append(f"Error reading the value from Keeper Vault for key={m[0]}, notation={m[1]} - Could not find a record with the UID.")
                result.append(item)

        # Process AWS-specific options (records, folders) before type-specific processing
        if (sync_type == 'aws' or sync_type == 'json') and (records or folders or folders_recursive):
            if sync_type == 'json':
                print(Fore.YELLOW + "Warning: --record, --folder, and --folder-recursive options generate JSON format that is only valid for --type=aws" + Style.RESET_ALL, file=sys.stderr)
            self._process_aws_records_and_folders(result, records, folders, folders_recursive, raw_json, maps)

        if sync_type == 'json':
            # type=json always outputs the dict structure as-is (no stringification)
            self._output(result)
        elif sync_type == 'azure':
            self.sync_azure(credentials, dry_run, preserve_missing, result)
        elif sync_type == 'aws':
            if not result:
                print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`, `--record TITLE_OR_UID`, `--folder FOLDER`, or `--folder-recursive FOLDER`" + Style.RESET_ALL, file=sys.stderr)
                return

            secretsmanager = self._get_aws_client(credentials)
            if secretsmanager is None:
                return

            # Separate entries: record-based, folder-based, and JSON format entries go through JSON path
            json_entries = [m for m in result if '+' in m["mapKey"] or
                           m.get("mapNotation", "").startswith("record:") or
                           m.get("mapNotation", "").startswith("folder:") or
                           m.get("mapNotation", "").startswith("folder-recursive:")]
            plain_entries = [m for m in result if '+' not in m["mapKey"] and
                            not m.get("mapNotation", "").startswith("record:") and
                            not m.get("mapNotation", "").startswith("folder:") and
                            not m.get("mapNotation", "").startswith("folder-recursive:")]

            # Process both but suppress individual outputs
            original_output = self._output
            self._output = lambda data, hide_data=False: None  # Suppress output temporarily

            if json_entries:
                self.sync_aws_json_with_client(secretsmanager, dry_run, preserve_missing, json_entries)
            if plain_entries:
                self.sync_aws_with_client(secretsmanager, dry_run, preserve_missing, plain_entries)

            # Output combined results
            self._output = original_output

            # For AWS dry-run: stringify srcValue dicts for flattened JSON (non-raw-json)
            # This shows what will actually be saved to AWS
            if dry_run:
                for item in result:
                    map_notation = item.get("mapNotation", "")
                    # Only process record/folder entries (not regular --map entries)
                    if (map_notation.startswith("record:") or
                        map_notation.startswith("folder:") or
                        map_notation.startswith("folder-recursive:")):
                        src_value = item.get("srcValue")
                        # If srcValue is a dict and not raw-json, stringify it
                        if isinstance(src_value, dict):
                            # Check if this is flattened JSON (all values are strings)
                            # Raw JSON has complex nested structures
                            is_flattened = all(isinstance(v, str) for v in src_value.values()) if src_value else True
                            if is_flattened:
                                # Stringify the flattened dict to show what AWS will store
                                item["srcValue"] = json.dumps(src_value, separators=(',', ':'))

            self._output(result, not dry_run)
        elif sync_type == 'gcp':
            self.sync_gcp(credentials, dry_run, preserve_missing, result)
        else:
            raise KsmCliException(f"Invalid option `--type {sync_type}`. Allowed values are (json, azure, aws, gcp).")

    def sync_azure(self, credentials:str="", dry_run=False, preserve_missing=False, maps: list=[]):
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import ClientSecretCredential
        except ImportError as ie:
            print(Fore.RED + "Missing Azure dependencies. To install missing packages run: \r\n" +
                Fore.YELLOW + "pip3 install azure-identity azure-keyvault-secrets\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing Azure Dependencies: " + str(ie))

        if not maps or len(maps) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL, file=sys.stderr)
            return

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL, file=sys.stderr)
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
            print(Fore.YELLOW + "Missing Vault Name in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not tenant_id:
            print(Fore.YELLOW + "Missing Tenant Id in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not client_id:
            print(Fore.YELLOW + "Missing Client Id in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not client_secret:
            print(Fore.YELLOW + "Missing Client Secret in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not(vault_name and tenant_id and client_id and client_secret):
            raise KsmCliException(f"Cannot find all required credentials in record UID {credentials}.")

        vault_url = f"https://{vault_name}.vault.azure.net"
        az_credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret)
        client = SecretClient(vault_url=vault_url, credential=az_credential)

        if dry_run:
            for m in maps:
                key = m["mapKey"]
                res = self._get_secret_az(client, key)
                val = res.get("value", None)
                m["dstValue"] = val.value if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    self.log.append(f"Error reading the value from Azure Vault for key={key}")
            self._output(maps)
        else:
            for m in maps:
                key = m["mapKey"]
                val = m["srcValue"]
                m["dstValue"] = m["srcValue"]
                if val is None:
                    if preserve_missing:
                        continue
                    else:
                        res = self._delete_secret_az(client, key)
                        err_msg = res.get("error", "")
                        if err_msg:
                            if "(SecretNotFound)" in err_msg:
                                self.logger.debug(f"Failed to delete key={key} - Already deleted.") # already deleted
                            else:
                                m["error"] = "Failed to delete remote key value pair."
                                self.log.append(f"Failed to delete key={key}")
                                self.logger.error("Failed to delete key=" + key)
                else:
                    res = self._set_secret_az(client, key, val)
                    if res.get("error", ""):
                        m["error"] = "Failed to set new value for the key."
                        self.log.append(f"Failed to set new value for key={key}")
                        self.logger.error("Failed to set new value for key=" + key)
            self._output(maps, True)

    def _get_aws_client(self, credentials: str = ""):
        """Common AWS client setup logic for both sync methods"""
        try:
            import boto3
        except ImportError as ie:
            print(Fore.RED + "Missing AWS dependencies. Install missing packages with: \r\n" +
                Fore.YELLOW + "pip3 install boto3\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing AWS Dependencies: " + str(ie))

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL, file=sys.stderr)
            return None

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
            print(Fore.YELLOW + "Missing AWS Access Key in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not aws_secret_access_key:
            print(Fore.YELLOW + "Missing AWS Secret Access Key in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not aws_region_name:
            print(Fore.YELLOW + "Missing AWS Region Name in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
        if not(aws_access_key_id and aws_secret_access_key and aws_region_name):
            raise KsmCliException(f"Cannot find all required credentials in record UID {credentials}.")

        secretsmanager = boto3.client('secretsmanager',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region_name
        )

        return secretsmanager

    def sync_aws_json_with_client(self, secretsmanager, dry_run=False, preserve_missing=False, maps: list = []):
        """Sync to AWS using JSON format with provided client"""

        # Group mappings by KMS key
        kms_groups = {}
        for m in maps:
            if '+' in m["mapKey"]:
                kms_key, json_key = m["mapKey"].split('+', 1)
                if kms_key not in kms_groups:
                    kms_groups[kms_key] = []
                kms_groups[kms_key].append({
                    "json_key": json_key,
                    "mapNotation": m["mapNotation"],
                    "srcValue": m["srcValue"],
                    "dstValue": None,
                    "original": m
                })
            else:
                # Handle record-based entries (no + in key)
                kms_key = m["mapKey"]
                if kms_key not in kms_groups:
                    kms_groups[kms_key] = []
                kms_groups[kms_key].append({
                    "json_key": None,  # Full JSON content
                    "mapNotation": m["mapNotation"],
                    "srcValue": m["srcValue"],
                    "dstValue": None,
                    "original": m
                })

        if dry_run:
            for kms_key, json_mappings in kms_groups.items():
                # Get current KMS value
                res = self._get_secret_aws(secretsmanager, kms_key)
                current_value = res.get("value", None)

                # Parse existing JSON or preserve plaintext
                existing_json = {}
                if current_value:
                    try:
                        existing_json = json.loads(current_value)
                    except (json.JSONDecodeError, TypeError):
                        # If it's not JSON, we'll preserve it under a special key
                        existing_json = {"_preserved_plaintext": current_value}

                # Show what would be in the JSON
                for mapping in json_mappings:
                    if mapping["json_key"] is None:
                        # Full JSON content (record-based)
                        mapping["original"]["dstValue"] = current_value
                    else:
                        # Partial JSON content (map-based)
                        mapping["original"]["dstValue"] = existing_json.get(mapping["json_key"])

                if not res.get("not_found", False) and res.get("error", ""):
                    for mapping in json_mappings:
                        mapping["original"]["error"] = "Error reading the value from AWS Secrets Manager."
                    self.log.append(f"Error reading the value from AWS Secrets Manager for key={kms_key}")

            self._output(maps)
        else:
            for kms_key, json_mappings in kms_groups.items():
                # Get current AWS value
                res = self._get_secret_aws(secretsmanager, kms_key)
                current_value = res.get("value", None)

                # Check if this is a record-based entry (full JSON replacement)
                is_record_based = any(mapping["json_key"] is None for mapping in json_mappings)

                if is_record_based:
                    # Handle record-based entries (full JSON replacement)
                    src_value = json_mappings[0]["srcValue"]  # Should be only one mapping for record-based
                    # srcValue is already a dict (from _generate_record_json)
                    src_json = src_value if isinstance(src_value, dict) else json.loads(src_value)

                    # Check if we need to preserve existing plaintext
                    if current_value:
                        try:
                            current_json = json.loads(current_value)

                            # Remove _preserved_plaintext from comparison
                            current_for_compare = {k: v for k, v in current_json.items() if k != "_preserved_plaintext"}
                            src_for_compare = {k: v for k, v in src_json.items() if k != "_preserved_plaintext"}

                            # Sort both JSON objects for comparison
                            current_sorted = json.dumps(current_for_compare, sort_keys=True, separators=(',', ':'))
                            new_sorted = json.dumps(src_for_compare, sort_keys=True, separators=(',', ':'))

                            if current_sorted == new_sorted:  # No changes needed
                                json_mappings[0]["original"]["dstValue"] = current_value  # Keep existing value with preserved plaintext
                                continue
                        except (json.JSONDecodeError, TypeError):
                            # Current value is plaintext, preserve it
                            src_json["_preserved_plaintext"] = current_value

                    # Update with new JSON content (possibly with preserved plaintext)
                    final_value = json.dumps(src_json, separators=(',', ':'))
                    res = self._set_secret_aws(secretsmanager, kms_key, final_value)
                    if res.get("error", ""):
                        json_mappings[0]["original"]["error"] = "Failed to set new value for the key."
                        self.log.append(f"Failed to set new value for key={kms_key}")
                        self.logger.error(f"Failed to set new value for key={kms_key}")
                    else:
                        json_mappings[0]["original"]["dstValue"] = final_value
                else:
                    # Handle map-based entries (partial JSON updates)
                    # Parse existing JSON or preserve plaintext
                    target_json = {}
                    preserved_plaintext = None
                    if current_value:
                        try:
                            target_json = json.loads(current_value)
                        except (json.JSONDecodeError, TypeError):
                            # Preserve existing plaintext value
                            preserved_plaintext = current_value

                    # Build the new JSON value
                    has_updates = False
                    for mapping in json_mappings:
                        json_key = mapping["json_key"]
                        src_value = mapping["srcValue"]

                        if src_value is not None:
                            if target_json.get(json_key) != src_value:
                                target_json[json_key] = src_value
                                has_updates = True
                            mapping["original"]["dstValue"] = src_value
                        elif not preserve_missing and json_key in target_json:
                            del target_json[json_key]
                            has_updates = True

                    # If we preserved plaintext and have other updates, add it
                    if preserved_plaintext and has_updates:
                        target_json["_preserved_plaintext"] = preserved_plaintext

                    # Store the JSON value
                    if has_updates:
                        new_value = json.dumps(target_json, separators=(',', ':'))
                        res = self._set_secret_aws(secretsmanager, kms_key, new_value)
                        if res.get("error", ""):
                            for mapping in json_mappings:
                                mapping["original"]["error"] = "Failed to set new value for the key."
                            self.log.append(f"Failed to set new value for key={kms_key}")
                            self.logger.error(f"Failed to set new value for key={kms_key}")
                # In JSON format: preserve KMS key with empty JSON value
                # if not target_json and not preserve_missing and preserved_plaintext is None:
                #     # Delete the KMS key if no values remain
                #     res = self._delete_secret_aws(secretsmanager, kms_key)
                #     err_msg = res.get("error", "")
                #     if err_msg:
                #         if "(ResourceNotFoundException)" not in err_msg:
                #             for mapping in json_mappings:
                #                 mapping["original"]["error"] = "Failed to delete remote key value pair."
                #             self.log.append(f"Failed to delete key={kms_key}")
                #             self.logger.error(f"Failed to delete key={kms_key}")

            self._output(maps, True)

    def sync_aws_json(self, credentials: str = "", dry_run=False, preserve_missing=False, maps: list = []):
        """Sync to AWS using JSON format for KMS keys (kms_key+json_key format)"""
        if not maps or len(maps) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL, file=sys.stderr)
            return

        secretsmanager = self._get_aws_client(credentials)
        if secretsmanager:
            self.sync_aws_json_with_client(secretsmanager, dry_run, preserve_missing, maps)

    def sync_aws_with_client(self, secretsmanager, dry_run=False, preserve_missing=False, maps: list = []):

        if dry_run:
            for m in maps:
                key = m["mapKey"]
                res = self._get_secret_aws(secretsmanager, key)
                val = res.get("value", None)
                m["dstValue"] = val if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    m["error"] = "Error reading the value from AWS Secrets Manager."
                    self.log.append(f"Error reading the value from AWS Secrets Manager for key={key}")
            self._output(maps)
        else:
            for m in maps:
                key = m["mapKey"]
                val = m["srcValue"]
                m["dstValue"] = m["srcValue"]
                if val is None:
                    if preserve_missing:
                        continue
                    else:
                        res = self._delete_secret_aws(secretsmanager, key)
                        err_msg = res.get("error", "")
                        if err_msg:
                            if "(ResourceNotFoundException)" in err_msg:
                                self.logger.debug("Failed to delete key=" + key) # alredy deleted
                            else:
                                m["error"] = "Failed to delete remote key value pair."
                                self.log.append(f"Failed to delete key={key}")
                                self.logger.error("Failed to delete key=" + key)
                else:
                    res = self._set_secret_aws(secretsmanager, key, val)
                    if res.get("error", ""):
                        m["error"] = "Failed to set new value for the key."
                        self.log.append(f"Failed to set new value for key={key}")
                        self.logger.error("Failed to set new value for key=" + key)
            self._output(maps, True)

    def sync_aws(self, credentials: str = "", dry_run=False, preserve_missing=False, maps: list = []):
        """Sync to AWS using plain format"""
        if not maps or len(maps) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL, file=sys.stderr)
            return

        secretsmanager = self._get_aws_client(credentials)
        if secretsmanager:
            self.sync_aws_with_client(secretsmanager, dry_run, preserve_missing, maps)

    def sync_gcp(self, credentials:str="", dry_run=False, preserve_missing=False, maps: list=[]):
        try:
            from google.cloud import secretmanager
            from google.oauth2 import service_account
        except ImportError as ie:
            print(Fore.RED + "Missing GCP dependencies. To install missing packages run: \r\n" +
                Fore.YELLOW + "pip3 install --upgrade google-cloud-secret-manager google-auth\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing GCP Dependencies: " + str(ie))

        if not maps or len(maps) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL, file=sys.stderr)
            return

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL, file=sys.stderr)
            return

        credentials = str(credentials).strip()
        secrets = self.cli.client.get_secrets(uids=[credentials])
        if len(secrets) == 0:
            raise KsmCliException("Cannot find the record with GCP credentials " + credentials)
        creds = secrets[0]

        # NB! Labels are case sensitive. Use Hidden Field fields in custom section of the record.
        app_credentials = self._get_secret_field(creds, GOOGLE_APPLICATION_CREDENTIALS_LABEL) or ""
        project_id = self._get_secret_field(creds, GOOGLE_CLOUD_PROJECT_ID_LABEL)

        if not project_id:
            print(Fore.YELLOW + "Missing Project Id in credentials record " + credentials + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException(f"Cannot find all required credentials in record UID {credentials}.")

        # If credentials are provided, the corresponding JSON is used first, then it defaults to ADC
        # If credentials are empty GCP client will use Application Default Credentials (ADC)
        # ADC can be acquired by running `gcloud auth application-default login` on same host
        # To specify non-default credentials location set env var: GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
        # https://cloud.google.com/docs/authentication/provide-credentials-adc

        client:secretmanager.SecretManagerServiceClient|None = None
        if str(app_credentials).strip():
            gcp_json_credentials_dict = json.loads(app_credentials)
            credentialz = service_account.Credentials.from_service_account_info(gcp_json_credentials_dict)
            client = secretmanager.SecretManagerServiceClient(credentials=credentialz)

        if client is None:
            client = secretmanager.SecretManagerServiceClient()

        if dry_run:
            for m in maps:
                key = m["mapKey"]
                res = self._get_secret_gcp(client, project_id, key)
                val = res.get("value", None)
                m["dstValue"] = val if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    self.log.append(f"Error reading the value from GCP for key={key}")
            self._output(maps)
        else:
            for m in maps:
                key = m["mapKey"]
                val = m["srcValue"]
                m["dstValue"] = m["srcValue"]
                if val is None:
                    if preserve_missing:
                        continue
                    else:
                        res = self._delete_secret_gcp(client, project_id, key)
                        err_msg = res.get("error", "")
                        if err_msg:
                            # '404 Secret [projects/123456789012/secrets/key_name] not found.'
                            if err_msg.startswith('404 ') and err_msg.endswith(' not found.'):
                                self.logger.debug(f"Failed to delete key={key} - Already deleted.") # already deleted
                            else:
                                m["error"] = "Failed to delete remote key value pair."
                                self.log.append(f"Failed to delete key={key}")
                                self.logger.error("Failed to delete key=" + key)
                else:
                    res = self._set_secret_gcp(client, project_id, key, val)
                    if res.get("error", ""):
                        m["error"] = "Failed to set new value for the key."
                        self.log.append(f"Failed to set new value for key={key}")
                        self.logger.error("Failed to set new value for key=" + key)
            self._output(maps, True)
