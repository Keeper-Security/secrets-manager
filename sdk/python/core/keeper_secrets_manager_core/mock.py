#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import base64
import uuid
import json
import time
from collections import deque
from requests import Response as RequestResponse
from keeper_secrets_manager_core.utils import encrypt_aes


class ResponseQueue:

    """Queue up response

    The is a FIFO queue. The queue can be loaded with mock Response instance that
    will be shift off when a request to get_response called.

    """

    def __init__(self, client, post_method=None):

        self.client = client

        # If the post_method is not defined, default to a built in one. All it will do is
        # return the next response in thr queue.
        if post_method is None:
            post_method = self.auto_responder_patch
        self.post_method = post_method

        self.queue = deque()

    def add_response(self, response):
        response.client = self.client
        if self.post_method is not None:
            response.patch_post_query(self.post_method)
        self.queue.append(response)

    def get_response(self, context):
        if len(self.queue) == 0:
            raise ValueError("Not enough queued responses. Cannot get response.")
        response = self.queue.popleft()
        return response.instance(context)

    def auto_responder_patch(self, _path, context, _payload_and_signature):
        return self.get_response(context)


class Response:

    """Mock a response from Secrets Manager Service

    secrets_manager_instance = SecretManger()
    mock_res = MockResponse(client=secrets_manager_instance)
    record = mock_res.add_record(title="My Record")
    record.login = "My Login"
    record.password = "My Password"
    record.add_file(name="My File 1")
    record.add_file(name="My File 2")

    response = mock_res.response()

    """

    def __init__(self, client=None, post_method=None, content=None, status_code=200, reason="OK", flags=None):

        """
        Flags is a dictionary where we can turn on/off stuff in the response to fake qwarks from other application and
        how they might store the data.

        * prune_custom_fields - If there is no custom fields, the 'custom' key is removed from the JSON.

        """

        self.client = client

        self.records = {}
        self.folders = {}

        self.content = content
        self.status_code = status_code
        self.reason = reason
        self.flags = flags

        # Monkey patch the _post_query method with a method that will return a
        # requests Response obj.
        if post_method is not None:
            self.patch_post_query(post_method)

        self.headers = {
            "Server": "keeper",
            "Content-Type": "application/octet-stream",
            "Connection": "keep-alive",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Expect-CT": "max-age=10, report-uri=\"https://keepersecurity.report-uri.com/r/d/ct/reportOnly\"",
            "Accept-Ranges": "bytes"
        }

    def patch_post_query(self, patch):
        """Patch keeper_secrets_manager.core.SecretsManager._post_query

        The patch is a method that accept three arguments.

          * path - Endpoint Path.
          * context - Context instance.
          * payload_and_signature - Dictionary containing encrypted data and signature.

        When SecretsManager posts a message to the Secrets Manager services, it will call the patch method
        instead. The patch method needs to return an instance of the requests Response.

        """

        if self.client is None:
            raise ValueError("The secrets manager client has not been set.")

        self.client._post_query = patch

    def dump(self, secret, flags=None):

        return {
            "encryptedAppKey": None,
            "folders": [self.folders[uid].dump(secret=secret, flags=flags) for uid in self.folders],
            "records": [self.records[uid].dump(secret=secret, flags=flags) for uid in self.records]
        }

    def instance(self, context):

        """ Return a requests Response instance filled in with mock response message

        res = Response.instance(context)

        The method requires an instance of keeper_secrets_manager_core.dto.payload.Context since that
        information on how to encrypt the response message.

        """

        res = RequestResponse()
        for key in self.headers:
            res.headers[key] = self.headers[key]
        res.headers["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

        # If canned content has not be set, the create content from records/folders.
        if self.content is None:
            json_str = json.dumps(self.dump(secret=context.clientKey, flags=self.flags))
            content = encrypt_aes(json_str.encode(), context.transmissionKey.key)
            res._content = content
            res.headers["Content-Length"] = str(len(content))

            res.status_code = 200
            res.reason = "OK"
        # Else return the canned content. This is useful to mock errors that return plain or json text.
        else:
            content = self.content
            if type(content) is str:
                content = content.encode()
            res._content = content
            res.status_code = self.status_code
            res.reason = self.reason

        return res

    def add_record(self, title=None, record_type=None, uid=None, record=None, keeper_record=None):

        if keeper_record is not None:
            record = Record.convert_keeper_record(keeper_record)
        elif record is None:
            record = Record(title=title, record_type=record_type, uid=uid)

        if isinstance(object, Record.__class__) is False:
            raise ValueError("Record being added to the response is not a "
                             "keeper_secrets_manager_core.mock.Record instance.")

        self.records[record.uid] = record
        return record

    def add_folder(self, uid=None, folder=None):

        if folder is None:
            folder = Folder(uid=uid)

        if isinstance(object, Folder.__class__) is False:
            raise ValueError("Folder being added to the response is not a "
                             "keeper_secrets_manager_core.mock.Folder instance.")

        self.folders[folder.uid] = folder
        return folder


class Folder:

    def __init__(self, uid=None):
        if uid is None:
            uid = str(uuid.uuid4())
        self.uid = uid
        self.records = {}

    def add_record(self, title=None, record_type=None, uid=None, record=None):

        if record is None:
            record = Record(record_type=record_type, uid=uid, title=title)

        if isinstance(object, Record.__class__) is False:
            raise ValueError("Record being added to the response is not a "
                             "keeper_secrets_manager_core.mock.Record instance.")

        self.records[record.uid] = record
        return record

    def dump(self, secret, flags=None):

        return {
            "folderUid": self.uid,
            "folderKey": base64.b64encode(encrypt_aes(secret, secret)).decode(),
            "records": [self.records[uid].dump(secret=secret, flags=flags) for uid in self.records]
        }


class File:

    def __init__(self, name, title=None, content_type=None, url=None, content=None, last_modified=None):
        self.uid = str(uuid.uuid4())
        self.secret_used = None

        self.name = name
        if title is None:
            title = self.name
        self.title = title
        if content_type is None:
            content_type = "text/plain"
        self.content_type = content_type
        if url is None:
            url = "http://localhost/{}".format(self.uid)
        self.url = url
        if content is None:
            content = "ABC123"
        self.content = content
        self.size = len(self.content)
        if last_modified is None:
            last_modified = int(time.time())
        self.last_modified = last_modified

    def downloadable_content(self):

        # The dump method will generate the content that the secrets manager would return. The
        # problem is we won't know the secret here. So the dump method needs to be run before
        # this method is called. The dump method will set the last/only secret used. We need to
        # encode the content with that secret.
        if self.secret_used is None:
            raise ValueError("The file has not be dump'd yet, Secret is unknown.")

        data = self.content
        if type(data) is not bytes:
            data = data.encode()

        return encrypt_aes(data, self.secret_used)

    def dump(self, secret, flags=None):

        # No special flags for download. Do this to make PEP8 happy for unused vars.
        if flags is not None:
            pass

        self.secret_used = secret
        d = {
            "name": self.name,
            "title": self.title,
            "size": self.size,
            "lastModified": self.last_modified,
            "type": self.content_type
        }
        data = json.dumps(d)
        file_data = {
            "fileUid": self.uid,
            "fileKey": base64.b64encode(encrypt_aes(secret, secret)).decode(),
            "data": base64.b64encode(encrypt_aes(data.encode(), secret)).decode(),
            "url": self.url,
            "thumbnailUrl": None
        }
        return file_data


class Record:

    def __init__(self, record_type=None, uid=None, title=None):

        if uid is None:
            uid = str(uuid.uuid4())
        if record_type is None:
            record_type = "login"

        self.uid = uid
        self.record_type = record_type
        self.title = title
        self.is_editable = False
        self.files = {}

        # Some default data
        self._fields = {
            "login": "Login {}".format(uid),
            "password": "******** {}".format(uid),
            "url": "http://localhost/{}".format(uid)
        }
        self._custom_fields = {}

    @staticmethod
    def convert_keeper_record(keeper_record):

        new_record = Record(
            record_type=keeper_record.type,
            uid=keeper_record.uid,
            title=keeper_record.title
        )
        for item in keeper_record.dict.get("fields"):
            new_record.field(
                field_type=item["type"],
                value=item["value"]
            )
        for item in keeper_record.dict.get("custom", []):
            new_record.custom_field(
                label=item["label"],
                field_type=item["type"],
                value=item["value"]
            )
        # TODO - Add files
        return new_record

    def field(self, field_type, value):
        if type(value) is not list:
            value = [value]
        self._fields[field_type] = value

    def custom_field(self, label, value, field_type="text"):
        if type(value) is not list:
            value = [value]
        if label not in self._custom_fields:
            self._custom_fields[label] = {}
        self._custom_fields[label][field_type] = value

    def add_file(self, name, title=None, content_type=None, url=None, content=None, last_modified=None):

        file = File(
            name=name,
            title=title,
            content_type=content_type,
            url=url,
            content=content,
            last_modified=last_modified
        )
        self.files[file.uid] = file
        return file

    def dump(self, secret, flags=None):

        # If no files, the JSON has null
        files = None
        if len(self.files) > 0:
            files = [self.files[uid].dump(secret=secret, flags=flags) for uid in self.files]

        fields = [{"type": "fileRef", "value": [uid for uid in self.files]}]
        for field_type in self._fields:
            fields.append({
                "type": field_type,
                "value": self._fields[field_type]
            })

        custom = []
        for label in self._custom_fields:
            for field_type in self._custom_fields[label]:
                custom.append({
                    "type": field_type,
                    "label": label,
                    "value": self._custom_fields[label][field_type]
                })

        record_data = {
            "title": self.title,
            "type": self.record_type,
            "fields": fields,
            "custom": custom
        }

        if flags is not None:
            # SecretsManager will not add a custom key if there is no custom fields. However the UI does.
            if flags.get("prune_custom_fields", False) is True and len(record_data["custom"]) == 0:
                record_data.pop("custom", None)
            # Remove fields if they do not have values.
            if flags.get("prune_empty_fields", False) is True:
                new_fields = []
                for field in record_data["fields"]:
                    if len(field.get("value")) > 0:
                        new_fields.append(field)
                record_data["fields"] = new_fields

        data = {
            "recordUid": self.uid,
            "recordKey": base64.b64encode(encrypt_aes(secret, secret)).decode(),
            "data": base64.b64encode(encrypt_aes(json.dumps(record_data).encode(), secret)).decode(),
            "isEditable": self.is_editable,
            "files": files
        }

        return data
