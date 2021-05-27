#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
#

class Context:

    def __init__(self, transmissionKey, clientId, clientKey, isBound, privateKey):
        self.transmissionKey = transmissionKey
        self.clientId = clientId
        self.clientKey = clientKey
        self.isBound = isBound
        self.privateKey = privateKey


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
        self.requestedRecords = []


class UpdatePayload:

    def __init__(self):
        self.clientVersion = None
        self.clientId = None
        self.recordUid = None
        self.data = None
