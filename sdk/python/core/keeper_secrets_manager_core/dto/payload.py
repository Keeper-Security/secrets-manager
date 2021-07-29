#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

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


class UpdatePayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUid = None
        self.data = None
