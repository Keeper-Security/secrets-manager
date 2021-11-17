import unittest
from unittest.mock import patch
import warnings
from click.testing import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_cli.__main__ import cli
import tempfile
import os
import json


class SecretInflateTest(unittest.TestCase):

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        # Because of click/testing.py:278 ResourceWarning: unclosed file <_io.FileIO ...
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_get(self):

        """ Test getting a list if secret records
        """

        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage({
            "hostname": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw=",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ==",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        address_res = mock.Response()
        address = address_res.add_record(title="Address Record")
        address.field("address", [{
            "street1": "100 West Street",
            "city": "Central City",
            "state": "AZ",
            "zip": "53211"
        }])

        card_res = mock.Response()
        card = card_res.add_record(title="Card Record")
        card.field("paymentCard", [{"cardNumber": "5555555555555555",
                                    "cardExpirationDate": "01/2021",
                                    "cardSecurityCode": "543"}])
        card.field("text", value=["Cardholder"], label="Cardholder Name")
        card.field("pinCode", "1234")
        card.field("addressRef", [address.uid])

        main_res = mock.Response()
        main = main_res.add_record(title="Main Record")
        main.field("cardRef", [card.uid])

        queue = mock.ResponseQueue(client=secrets_manager)

        # profile init
        queue.add_response(main_res)

        queue.add_response(main_res)
        queue.add_response(card_res)
        queue.add_response(address_res)

        queue.add_response(main_res)
        queue.add_response(card_res)
        queue.add_response(address_res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(
                token='rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ'
            )

            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'get', '-u', main.uid, '--unmask', '--json'],
                                   catch_exceptions=False)
            result = json.loads(result.output)

            card_ref = next((item for item in result["fields"] if item["type"] == "cardRef"), None)
            self.assertIsNotNone(card_ref, "could not find card ref")
            value = card_ref.get("value")[0]

            self.assertEqual("5555555555555555", value.get("cardNumber"), "did not find the card number")
            self.assertEqual("100 West Street", value.get("street1"), "did not find street1")

            result = runner.invoke(cli, ['secret', 'get', '-u', main.uid, '--unmask', '--json', '--deflate'],
                                   catch_exceptions=False)
            result = json.loads(result.output)
            print(result)
