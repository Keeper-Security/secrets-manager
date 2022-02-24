import unittest
from keeper_secrets_manager_helper.record_type import RecordType
from keeper_secrets_manager_helper.v3.record_type import get_class_by_type, make_class_name
import json
import tempfile


class ParserTest(unittest.TestCase):

    # def test_did_i_work(self):
    #    p = rt.Phone()
    #    print(p.field_map)
    #    print(p.generate_template())

    def test_get_class(self):
        b = get_class_by_type("bankAccount")()
        print(b.generate_template("json"))
        print(b.generate_template("yaml"))

    def test_custom_class_name(self):

        name = make_class_name("Keeper VPN - Azure Login")
        self.assertEqual("KeeperVpnAzureLogin", name)

        name = make_class_name("Record 123 !!!! #####")
        self.assertEqual("Record123", name)

        name = make_class_name("#####")
        self.assertEqual("", name)

    def test_load_record_type_file(self):

        data = {
            "version": "v3",
            "kind": "KeeperRecordType",
            "data": [
                {
                    "class": "MyCustom",
                    "name": "myCustom",
                    "fields": [
                        {"type": "text", "label": "Text One"},
                        {"type": "text", "label": "Text Two"}
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json") as fh:
            fh.write(json.dumps(data))
            fh.seek(0)
            RecordType.load_record_types(fh.name)
            fh.close()

        try:
            get_class_by_type("myCustom")
        except ImportError as err:
            self.fail("Could not find class MyCustom: " + str(err))

    def test_load_commander_record_type_file(self):

        data = [
            {
                "recordTypeId": 35,
                "content":
                    "{\"$id\":\"Azure Login\",\"fields\":"
                    "[{\"$ref\":\"fileRef\",\"label\":\"File or Photo\"},"
                    "{\"$ref\":\"login\",\"label\":\"Login\"},"
                    "{\"$ref\":\"password\",\"label\":\"Password\",\"required\":true,"
                    "\"enforceGeneration\":false,\"privacyScreen\":false,"
                    "\"complexity\":{\"length\":8,\"caps\":0,\"lowercase\":0,\"digits\":0,\"special\":0}},"
                    "{\"$ref\":\"text\",\"label\":\"System Login\",\"required\":true},"
                    "{\"$ref\":\"secret\",\"label\":\"System Password / Pin Code\"},"
                    "{\"$ref\":\"url\",\"label\":\"Keeper VPN Wiki\",\"required\":true},"
                    "{\"$ref\":\"url\",\"label\":\"Password Best Practices FAQ's and Tips\",\"required\":true}]}"
            }
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".json") as fh:
            fh.write(json.dumps(data))
            fh.seek(0)
            RecordType.load_record_types(fh.name)
            fh.close()

        try:
            get_class_by_type("Azure Login")
        except ImportError as err:
            self.fail("Could not find class Azure Login: " + str(err))
