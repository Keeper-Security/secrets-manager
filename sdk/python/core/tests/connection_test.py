import unittest
import tempfile
import json

from keepercommandersm import Commander


class ConnectionTest(unittest.TestCase):

    @unittest.skip
    def test_get_via_client_key(self):

        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            print(fh.name)
            c = Commander(
                server="dev.keepersecurity.com",
                client_key="ODTBfvKeHlXMkZT905ic-ngFNL2SnqHhnwX2qtY5KNs",
                config_file_location=fh.name
            )
            print(c.get_secrets())

    def test_via_config(self):
        with tempfile.NamedTemporaryFile("w") as fh:
            fh.write(
                json.dumps({
                    "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
                    "clientId": "snqj0FdSFIHPQjIGirxORR4wUqp6CVR-gTyboiMY2"
                                "12qzQJkBlY_H7Tt-zy2i1FSdnTraOUSVYlsyNGKW7iv1Q",
                    "clientKey": "ODTBfvKeHlXMkZT905ic-ngFNL2SnqHhnwX2qtY5KNs",
                    "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQ"
                                  "g6Mb4y-znZhhd8waZzWff84mhYg67lOAUaoFjr-3JiUuhRA"
                                  "NCAASyhlLG4KwEWPmSIZFyQ4kIzSqz5df1fXuVx2zKw6ouF"
                                  "G1mii6xLGWftz8r8ihJCgtU7fCN6uaA6dFZHNmrxV4x"
                })
            )
            fh.seek(0)

            print(fh.name)
            c = Commander(
                config_file_location=fh.name
            )
            print(c.get_secrets())
