import os
import unittest
from keeper_secrets_manager_helper.record import Record
from keeper_secrets_manager_helper.exception import FileSyntaxException
import yaml
import json
import tempfile


class RecordFileTest(unittest.TestCase):

    @staticmethod
    def _make_record_data():

        return {
            "version": "v3",
            "kind": "KeeperRecord",
            "data": [
                {
                    "recordType": "bankAccount",
                    "title": "Bank Account",
                    "fields": [
                        {
                            "type": "bankAccount",
                            "value": {
                                "accountType": "Checking",
                                "routingNumber": "ROUTING",
                                "accountNumber": "ACCOUNT"
                            }
                        },
                        {
                            "type": "name",
                            "value": {
                                "first": "John",
                                "last": "Smith"
                            }
                        },
                        {
                            "type": "login",
                            "value": "my_login"
                        }
                    ]
                },
                {
                    "recordType": "login",
                    "title": "Login",
                    "fields": [
                        {
                            "type": "login",
                            "value": "my_login"
                        }
                    ]
                }
            ]
        }

    def test_load_template_files(self):

        data = self._make_record_data()

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
                fh.write(yaml.dump(data))
                fh.seek(0)
                records = Record.create_from_file(fh.name)
                self.assertEqual(2, len(records), "did not get 2 records")
                fh.close()

            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                fh.write(json.dumps(data))
                fh.seek(0)
                records = Record.create_from_file(fh.name)
                self.assertEqual(2, len(records), "did not get 2 records")
                fh.close()
        finally:
            try:
                os.unlink(fh.name)
            except IOError:
                pass

    def test_bad_yaml_template_file(self):

        # Bad spot is the tab
        bad_yaml = """
        version: v3
        kind: KeeperRecord
        data:
          - recordType: Login
        \ttitle: My Title
            fields:
              - type: login
        """

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
                fh.write(bad_yaml)
                fh.seek(0)
                Record.create_from_file(fh.name)
                fh.close()
        except FileSyntaxException as err:
            self.assertRegex(str(err), r'The YAML has problems around row 6, column 9')
        except Exception as err:
            self.fail("Got an exception: " + str(err))
        finally:
            try:
                os.unlink(fh.name)
            except IOError:
                pass

    def test_bad_json_template_file(self):

        # Bad spot is missing quote for title key
        bad_json = """
        {
          "version": "v3",
          "kind": "KeeperRecord",
          "data": [{
            "recordType": "Login",
            title": "My Title",
            "fields": [{
              "type": "login"
            }]
          }]
        }
        """

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                fh.write(bad_json)
                fh.seek(0)
                Record.create_from_file(fh.name)
                fh.close()
        except FileSyntaxException as err:
            self.assertRegex(str(err), r'The JSON had problems: Expecting property name enclosed in double quotes'
                                       r' around row 7, column 13')
        except Exception as err:
            self.fail("Got an exception: " + str(err))
        finally:
            try:
                os.unlink(fh.name)
            except IOError:
                pass
