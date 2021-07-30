import unittest
import json
import os

from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core import mock
from requests import HTTPError


class ExceptionTest(unittest.TestCase):

    def setUp(self):

        self.orig_working_dir = os.getcwd()

    def tearDown(self):

        os.chdir(self.orig_working_dir)

    def test_our_exception(self):

        """Exceptions the Secrets Manager server will send that have meaning.
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res_queue = mock.ResponseQueue(client=secrets_manager)

        # Make the error message
        error_json = {
            "path": "https://fake.keepersecurity.com/api/rest/sm/v1/get_secret, POST, python-requests/2.25.1",
            "additional_info": "",
            "location": "default exception manager - api validation exception",
            "error": "access_denied",
            "message": "Signature is invalid"
        }

        res = mock.Response(content=json.dumps(error_json).encode(), status_code=403)
        res_queue.add_response(res)

        try:
            secrets_manager.get_secrets()
        except KeeperError as err:
            self.assertRegex(err.message, r'Signature is invalid', 'did not get correct error message')

    def test_not_our_exception(self):

        """Generic message not specific to the Secrets Manager server.
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res_queue = mock.ResponseQueue(client=secrets_manager)

        res = mock.Response(content=b"Bad Gateway", status_code=502)
        res_queue.add_response(res)

        try:
            secrets_manager.get_secrets()
        except HTTPError as err:
            self.assertRegex(str(err), r'Bad Gateway', 'did not get correct error message')

    def test_key_rotation(self):

        """Special exception for rotating the public key.
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res_queue = mock.ResponseQueue(client=secrets_manager)

        res_1 = mock.Response()
        mock_record_1 = res_1.add_record(title="My Record")
        mock_record_1.field("login", "My Login")
        mock_record_1.field("password", "My Password")

        res_2 = mock.Response()
        mock_record_2 = res_2.add_record(title="My Record")
        mock_record_2.field("login", "KEY CHANGE")
        mock_record_2.field("password", "My Password")

        # KEY ROTATION ERROR. error needs to be key.
        error_json = {
            "error": "key",
            "key_id": "2"
        }

        res_queue.add_response(res_1)
        res_queue.add_response(mock.Response(content=json.dumps(error_json).encode(), status_code=403))
        res_queue.add_response(res_2)

        records = secrets_manager.get_secrets()
        self.assertEqual(len(records), 1, "didn't get 1 records")

        # This one should get a key error, then retry to get record.
        records = secrets_manager.get_secrets()
        self.assertEqual(len(records), 1, "didn't get 1 records")

        self.assertEqual("2", secrets_manager.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
                         "didn't get correct key id")
        self.assertEqual(mock_record_2.uid, records[0].uid, "did not get correct record")

