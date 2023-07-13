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

class Context:

    def __init__(self, transmission_key, client_id, client_key):
        self.transmissionKey = transmission_key
        self.clientId = client_id
        self.clientKey = client_key


class TransmissionKey:

    def __init__(self, publicKeyId, key, encryptedKey):
        self.publicKeyId = publicKeyId
        self.key = key
        self.encryptedKey = encryptedKey


class GetPayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.publicKey = None
        self.requestedRecords = None
        self.requestedFolders = None


class CreatePayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUid = None
        self.recordKey = None
        self.folderUid = None
        self.folderKey = None
        self.data = None
        self.subFolderUid = None


class DeletePayload:
    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUids = None


class CreateFolderPayload:
    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.folderUid = None
        self.sharedFolderUid = None
        self.sharedFolderKey = None
        self.data = None
        self.parentUid = None


class UpdateFolderPayload:
    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.folderUid = None
        self.data = None


class DeleteFolderPayload:
    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.folderUids = None
        self.forceDeletion = False


class FileUploadPayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.fileRecordUid = None
        self.fileRecordKey = None
        self.fileRecordData = None
        self.ownerRecordUid = None
        self.ownerRecordData = None
        self.linkKey = None
        self.fileSize = None


class UpdatePayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUid = None
        self.data = None
        self.revision = None
        self.transactionType = None  # 'general' or 'rotation'


class CompleteTransactionPayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUid = None


class EncryptedPayload:

    def __init__(self, encrypted_payload, signature):
        self.encrypted_payload = encrypted_payload
        self.signature = signature


class KSMHttpResponse:

    def __init__(self, status_code, data, http_response=None):
        self.status_code = status_code
        self.data = data
        self.http_response = http_response


class QueryOptions:

    def __init__(self, records_filter, folders_filter):
        self.records_filter = records_filter
        self.folders_filter = folders_filter


class CreateOptions:

    def __init__(self, folder_uid, subfolder_uid):
        self.folder_uid = folder_uid
        self.subfolder_uid = subfolder_uid
