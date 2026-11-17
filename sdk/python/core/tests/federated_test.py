import json
import os
import tempfile
import unittest
from unittest.mock import patch

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.crypto import CryptoUtils
from keeper_secrets_manager_core.dto.payload import EncryptedPayload, TransmissionKey
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core.utils import base64_to_bytes, bytes_to_string


def federated_config(skip=None):
    """A federated client config as Commander writes it: no privateKey, authType oauth"""
    config = MockConfig.make_config(skip_list=['privateKey', 'clientKey'] + (skip or []))
    config['authType'] = 'oauth'
    return InMemoryKeyValueStorage(json.dumps(config))


class FederatedTest(unittest.TestCase):

    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        for name in ('KSM_FEDERATED_TOKEN_FILE', 'KSM_FEDERATED_TOKEN', 'KSM_CONFIG', 'KSM_TOKEN'):
            os.environ.pop(name, None)

    def tearDown(self):
        self.env.stop()

    @staticmethod
    def queue_responses(secrets_manager, count=1):
        """Queues mock get_secret responses and records what the client sent"""
        sent = []
        queue = mock.ResponseQueue(client=secrets_manager)

        def post(url, transmission_key, encrypted, verify_ssl_certs=True, proxy_url=None):
            sent.append((transmission_key, encrypted))
            return queue.get_response(transmission_key)

        queue.post_method = post
        for _ in range(count):
            response = mock.Response()
            response.add_record(title="Federated Record").field("login", "fed-login")
            queue.add_response(response)
        return sent

    @staticmethod
    def sent_token(transmission_key, encrypted):
        scheme, value = encrypted.authorization.split(' ')
        assert scheme == 'EncryptedBearer', scheme
        return bytes_to_string(CryptoUtils.decrypt_aes(base64_to_bytes(value), transmission_key.key))

    def test_get_secrets_sends_encrypted_bearer(self):
        config = federated_config()
        secrets_manager = SecretsManager(config=config, federated_token='header.payload.signature')
        sent = self.queue_responses(secrets_manager)

        records = secrets_manager.get_secrets()

        self.assertEqual(1, len(records))
        self.assertEqual('fed-login', records[0].field('login', single=True))
        transmission_key, encrypted = sent[0]
        self.assertIsNone(encrypted.signature)
        self.assertEqual('header.payload.signature', self.sent_token(transmission_key, encrypted))
        payload = json.loads(CryptoUtils.decrypt_aes(encrypted.encrypted_payload, transmission_key.key))
        self.assertEqual(config.get(ConfigKeys.KEY_CLIENT_ID), payload['clientId'])
        # a federated client never binds, so it never sends a public key
        self.assertIsNone(payload.get('publicKey'))
        # and never gets one: no private key is generated into the config
        self.assertIsNone(config.get(ConfigKeys.KEY_PRIVATE_KEY))

    def test_callable_token_is_called_for_every_request(self):
        tokens = iter(['token-1', 'token-2'])
        secrets_manager = SecretsManager(config=federated_config(), federated_token=lambda: next(tokens))
        sent = self.queue_responses(secrets_manager, count=2)

        secrets_manager.get_secrets()
        secrets_manager.get_secrets()

        self.assertEqual(['token-1', 'token-2'], [self.sent_token(*s) for s in sent])

    def test_token_file_is_reread_for_every_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = os.path.join(tmp, 'token')
            with open(token_file, 'w') as fh:
                fh.write('file-token-1\n')
            os.environ['KSM_FEDERATED_TOKEN_FILE'] = token_file
            secrets_manager = SecretsManager(config=federated_config())
            sent = self.queue_responses(secrets_manager, count=2)

            secrets_manager.get_secrets()
            with open(token_file, 'w') as fh:
                fh.write('file-token-2')     # rotated, e.g. by the kubelet
            secrets_manager.get_secrets()

        self.assertEqual(['file-token-1', 'file-token-2'], [self.sent_token(*s) for s in sent])

    def test_token_from_environment(self):
        os.environ['KSM_FEDERATED_TOKEN'] = 'env-token'
        secrets_manager = SecretsManager(config=federated_config())
        sent = self.queue_responses(secrets_manager)

        secrets_manager.get_secrets()

        self.assertEqual('env-token', self.sent_token(*sent[0]))

    def test_empty_token_is_rejected(self):
        secrets_manager = SecretsManager(config=federated_config(), federated_token=lambda: '  ')
        self.queue_responses(secrets_manager)
        with self.assertRaises(KeeperError):
            secrets_manager.get_secrets()

    def test_invalid_federated_configs(self):
        with self.assertRaisesRegex(ValueError, 'needs a federated token'):
            SecretsManager(config=federated_config())
        with self.assertRaisesRegex(ValueError, 'missing "appKey"'):
            SecretsManager(config=federated_config(skip=['appKey']), federated_token='t')
        with self.assertRaisesRegex(ValueError, 'missing "clientId"'):
            SecretsManager(config=federated_config(skip=['clientId']), federated_token='t')
        with self.assertRaisesRegex(ValueError, "One Time Token"):
            SecretsManager(token='US:abc', config=federated_config(), federated_token='t')

    def test_post_function_authorization_header(self):
        transmission_key = TransmissionKey('7', b'k' * 32, b'encrypted-key')
        captured = []

        class Rs:
            status_code = 200
            content = b''

        def fake_post(url, headers=None, **kwargs):
            captured.append(headers)
            return Rs()

        with patch('requests.post', side_effect=fake_post):
            SecretsManager.post_function('https://h/api/rest/sm/v1/get_secret', transmission_key,
                                         EncryptedPayload(b'data', None, 'EncryptedBearer abc'))
            SecretsManager.post_function('https://h/api/rest/sm/v1/get_secret', transmission_key,
                                         EncryptedPayload(b'data', b'sig'))

        self.assertEqual('EncryptedBearer abc', captured[0]['Authorization'])
        self.assertTrue(captured[1]['Authorization'].startswith('Signature '))

    def test_signed_client_unchanged(self):
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_json()))
        self.assertFalse(secrets_manager.is_federated())
        sent = self.queue_responses(secrets_manager)

        secrets_manager.get_secrets()

        _, encrypted = sent[0]
        self.assertIsNotNone(encrypted.signature)
        self.assertIsNone(encrypted.authorization)


if __name__ == '__main__':
    unittest.main()
