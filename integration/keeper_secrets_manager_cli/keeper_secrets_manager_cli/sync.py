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
import sys
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

    def sync_values(self, type:str, credentials:str="", dry_run=False, preserve_missing=False, map=None):
        map = map or []
        result = []

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
                result.append({"mapKey": m[0], "mapNotation": m[1], "srcValue": value, "dstValue": None})
            except Exception as err:
                item = {"mapKey": m[0], "mapNotation": m[1], "srcValue": None, "dstValue": None}
                errstr = str(err)
                if errstr.startswith("Could not find a record with the UID "):
                    # stats["missingRecords"].add(errstr.split(' ')[-1])
                    item["error"] = "Error reading the value from Keeper Vault - Could not find a record with the UID."
                    self.log.append(f"Error reading the value from Keeper Vault for key={m[0]}, notation={m[1]} - Could not find a record with the UID.")
                result.append(item)

        if type == 'json':
            self._output(result)
        elif type == 'azure':
            self.sync_azure(credentials, dry_run, preserve_missing, result)
        elif type == 'aws':
            self.sync_aws(credentials, dry_run, preserve_missing, result)
        elif type == 'gcp':
            self.sync_gcp(credentials, dry_run, preserve_missing, result)
        else:
            raise KsmCliException(f"Invalid option `--type {type}`. Allowed values are (json, azure, aws, gcp).")

    def sync_azure(self, credentials:str="", dry_run=False, preserve_missing=False, map:list=[]):
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import ClientSecretCredential
        except ImportError as ie:
            print(Fore.RED + "Missing Azure dependencies. To install missing packages run: \r\n" +
                Fore.YELLOW + "pip3 install azure-identity azure-keyvault-secrets\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing Azure Dependencies: " + str(ie))

        if not map or len(map) == 0:
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
            for m in map:
                key = m["mapKey"]
                res = self._get_secret_az(client, key)
                val = res.get("value", None)
                m["dstValue"] = val.value if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    self.log.append(f"Error reading the value from Azure Vault for key={key}")
            self._output(map)
        else:
            for m in map:
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
            self._output(map, True)

    def sync_aws(self, credentials:str="", dry_run=False, preserve_missing=False, map:list=[]):
        try:
            import boto3
        except ImportError as ie:
            print(Fore.RED + "Missing AWS dependencies. Install missing packages with: \r\n" +
                Fore.YELLOW + "pip3 install boto3\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing AWS Dependencies: " + str(ie))

        if not map or len(map) == 0:
            print(Fore.YELLOW + "Nothing to sync - please provide some values with `--map \"key\" \"value\"`" + Style.RESET_ALL, file=sys.stderr)
            return

        if not credentials or not str(credentials).strip():
            print(Fore.YELLOW + "Missing credentials' record UID - please provide UID with `--credentials <UID>`" + Style.RESET_ALL, file=sys.stderr)
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

        if dry_run:
            for m in map:
                key = m["mapKey"]
                res = self._get_secret_aws(secretsmanager, key)
                val = res.get("value", None)
                m["dstValue"] = val if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    m["error"] = "Error reading the value from AWS Secrets Manager."
                    self.log.append(f"Error reading the value from AWS Secrets Manager for key={key}")
            self._output(map)
        else:
            for m in map:
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
            self._output(map, True)

    def sync_gcp(self, credentials:str="", dry_run=False, preserve_missing=False, map:list=[]):
        try:
            from google.cloud import secretmanager
            from google.oauth2 import service_account
        except ImportError as ie:
            print(Fore.RED + "Missing GCP dependencies. To install missing packages run: \r\n" +
                Fore.YELLOW + "pip3 install --upgrade google-cloud-secret-manager google-auth\r\n" + Style.RESET_ALL, file=sys.stderr)
            raise KsmCliException("Missing GCP Dependencies: " + str(ie))

        if not map or len(map) == 0:
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
            for m in map:
                key = m["mapKey"]
                res = self._get_secret_gcp(client, project_id, key)
                val = res.get("value", None)
                m["dstValue"] = val if val else None
                if not res.get("not_found", False) and res.get("error", ""):
                    self.log.append(f"Error reading the value from GCP for key={key}")
            self._output(map)
        else:
            for m in map:
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
            self._output(map, True)
