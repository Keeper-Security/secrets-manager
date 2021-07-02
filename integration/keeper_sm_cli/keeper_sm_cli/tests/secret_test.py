import unittest
from unittest.mock import patch
import warnings
from click.testing import CliRunner
from keepercommandersm.core import Commander
from keepercommandersm.storage import InMemoryKeyValueStorage
from keepercommandersm import mock
from ..secret import Secret
from ..profile import Profile
from ..__main__ import cli
import tempfile
import json
import re
import os
from requests import Response


class SecretTest(unittest.TestCase):

    # TODO: PyCharm doesn't like the type of 'cli', but it works. Find out how to make PyCharm not warn about this.
    #  Expected type 'BaseCommand', got '(ctx: Any, ini_file: Any, profile_name: Any, output: Any) -> Any' instead

    def setUp(self) -> None:
        self.orig_dir = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

        # Because of click/testing.py:278 ResourceWarning: unclosed file <_io.FileIO ...
        warnings.simplefilter("ignore", ResourceWarning)

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

    def test_list(self):

        """ Test getting a list if secret records
        """

        commander = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res = mock.Response()

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        two = res.add_record(title="My Record 2")
        two.field("login", "My Login 2")
        two.field("password", "My Password 2")
        two.custom_field("My Custom 1", "custom2")

        fast_lookup = {
            "My Record 1": one.uid,
            "My Record 2": two.uid,
        }

        queue = mock.ResponseQueue(client=commander)
        # JSON Output
        queue.add_response(res)
        # Text Output
        queue.add_response(res)

        with patch('keeper_sm_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = commander

            # JSON Ouput
            with tempfile.NamedTemporaryFile() as tf:
                runner = CliRunner()
                result = runner.invoke(cli, ['-o', tf.name, 'secret', 'list', '--json'], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")
                tf.seek(0)
                secret_list = json.load(tf)
                for record in secret_list:
                    self.assertEqual(fast_lookup[record["title"]], record["uid"], "Bad UID for record: {}".format(
                        record["uid"]))
                tf.close()

            # Text Output
            with tempfile.NamedTemporaryFile() as tf:
                runner = CliRunner()
                result = runner.invoke(cli, ['-o', tf.name, 'secret', 'list'], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")
                tf.seek(0)
                table = tf.read()
                self.assertIsNotNone(re.search(one.uid, table.decode(), flags=re.MULTILINE),
                                     "did not find UID in table")
                tf.close()

    def test_get(self):

        commander = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.field("url", [])
        one.custom_field("My Custom 1", "custom1")
        one.custom_field("blank", [])
        one.custom_field("json", [{'hi': "there"}])
        one.add_file("my.mp4")
        one.add_file("my.cert")

        # TODO: Add dup custom fields. The problem is the mock record won't let you :(

        queue = mock.ResponseQueue(client=commander)
        for test in range(0, 5):
            queue.add_response(res)

        with patch('keeper_sm_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = commander

            # JSON Output to file
            with tempfile.NamedTemporaryFile() as tf:
                runner = CliRunner()
                result = runner.invoke(cli, ['-o', tf.name, 'secret', 'get', '-u', one.uid, '--json'],
                                       catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")
                tf.seek(0)
                secret = json.load(tf)
                self.assertEqual(one.uid, secret["uid"], "didn't get the correct uid for secret")
                tf.close()

            # JSON Output w/ JQ to stdout
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'get', '-u', one.uid, '--json',
                '--query', 'fields[*]'
            ], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")
            fields = json.loads(result.output)
            self.assertEqual(4, len(fields), "didn't find 4 objects in array")

            # Text Output to file
            with tempfile.NamedTemporaryFile() as tf:
                runner = CliRunner()
                result = runner.invoke(cli, ['-o', tf.name, 'secret', 'get', '-u', one.uid], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")
                tf.seek(0)
                table = tf.read()
                self.assertIsNotNone(re.search(one.uid, table.decode(), flags=re.MULTILINE),
                                     "did not find UID in table")
                tf.close()

            # Text Output w/ JQ to stdout (force results to array, then adjust jq to handle arrays)

            # The single record will be converted to an array, so the first JSONPath expression needs to
            # reference an array.

            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'get', '-u', one.uid,
                '--query', '[*].fields[*].type',
                '--force-array'
            ], catch_exceptions=True)
            rows = result.output.split("\n")
            self.assertEqual(4, len(rows), "found 4 rows")
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

    def test_download(self):

        commander = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        mock_content = "ABC123"

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        mocked_file = one.add_file("my.mp4", content=mock_content)

        queue = mock.ResponseQueue(client=commander)
        queue.add_response(res)

        def mock_download_get(_):
            mock_res = Response()
            mock_res.status_code = 200
            mock_res.reason = "OK"
            mock_res._content = mocked_file.downloadable_content()
            return mock_res

        with patch('requests.get', side_effect=mock_download_get) as mock_get:
            with patch('keeper_sm_cli.KeeperCli.get_client') as mock_client:
                mock_client.return_value = commander

                with tempfile.NamedTemporaryFile() as tf:
                    runner = CliRunner()
                    result = runner.invoke(cli, [
                        'secret', 'download', '-u', one.uid, '--name', 'my.mp4',
                        '--file-output', tf.name
                    ], catch_exceptions=False)
                    tf.seek(0)
                    the_content = tf.read()
                    self.assertEqual(0, result.exit_code, "the exit code was not 0")
                    self.assertEqual(mock_content, the_content.decode(), 'the downloaded file does not match')
            self.assertEqual(1, mock_get.call_count, "the mock get call count is not 1")

    def test_notation(self):

        commander = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=commander)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_sm_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = commander

            # Good one
            notation = "keeper://{}/{}/{}".format(one.uid, "field", "login")
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', notation], catch_exceptions=False)
            self.assertEqual("My Login 1", result.output, "Did not get My Login 1 via stdout")
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            # Bad one
            bad_notation = "IM_BAD!!!!"
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', bad_notation], catch_exceptions=False)
            self.assertRegex(result.output, r'Could not parse the notation', 'got bad parse error')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # Too many / parameters
            too_much_notation = "keeper://{}/{}/{}/BAD".format(one.uid, "field", "login")
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', too_much_notation], catch_exceptions=False)
            self.assertRegex(result.output, r'Could not parse the notation', 'got bad parse error')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # Bad field
            notation = "keeper://{}/{}/{}".format(one.uid, "field", "im_a_bad_field")
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', notation], catch_exceptions=False)
            self.assertRegex(result.output, r'Cannot find the field', 'got an error for bad field')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

    def test_update(self):
        """Test updating an existing record
        """

        commander = Commander(config=InMemoryKeyValueStorage({
            "server": "fake.keepersecurity.com",
            "appKey": "9vVajcvJTGsa2Opc_jvhEiJLRKHtg2Rm4PAtUoP3URw",
            "clientId": "rYebZN1TWiJagL-wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW-NNHDaq_8SQQ2sOYYT1Nhk5Ya_SkQ",
            "clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo",
            "privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU-_LBMQQGfJAycwOtx9djH0Y"
                          "EvBT-hRANCAASB1L44QodSzRaIOhF7f_2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xC"
                          "jhKMhHQFaHYI"
        }))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("my_custom", "custom1")

        queue = mock.ResponseQueue(client=commander)

        # The good one
        queue.add_response(res)
        queue.add_response(mock.Response(content="", status_code=200))

        # The bad field
        queue.add_response(res)

        # Bad server response
        queue.add_response(res)
        queue.add_response(mock.Response(content="I hate you and your little dog.", status_code=500))

        with patch('keeper_sm_cli.KeeperCli.get_client') as mock_client:
            mock_client.return_value = commander

            # Because of click/testing.py:278 ResourceWarning: unclosed file <_io.FileIO ...
            warnings.simplefilter("ignore", ResourceWarning)

            # The good one!
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field', '"login=New Login"',
                '--custom-field', '"my_custom=New Custom text"',
            ], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            # Blow up on bad field.
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field', '"login=New Login"',
                '--field', 'bad_field=HERE',
                '--custom-field', '"my_custom=New Custom text"',
            ], catch_exceptions=False)
            self.assertRegex(result.output, r'Cannot find the field', 'did not get correct error message')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # Blow up on server response
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field', '"login=New Login"',
                '--custom-field', '"my_custom=New Custom text"',
            ], catch_exceptions=False)
            # TODO - Improve SDK error messages. We don't have one for save errors.
            self.assertRegex(result.output, r'Could not save record', 'did not get correct error message for save')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

    def test_kv_split(self):
        """Test splitting the key/value pairs
        """

        # The simple
        key, value = Secret._split_kv("foo=bar")
        self.assertEqual("foo", key, "key is not foo")
        self.assertEqual("bar", value, "key is not bar")

        # = in the key
        key, value = Secret._split_kv("\=foo\==bar")
        self.assertEqual("=foo=", key, "key is not =foo=")
        self.assertEqual("bar", value, "key is not bar, the 2nd")

        # = in the key and value
        key, value = Secret._split_kv("\=foo\==\=bar\=")
        self.assertEqual("=foo=", key, "key is not =foo=")
        self.assertEqual("=bar=", value, "key is not =bar=")

        # = in the key and value, with escaped escape character in key
        key, value = Secret._split_kv("\=foo\\\\=\=bar\=")
        self.assertEqual("=foo\\\\", key, "key is not =foo=")
        self.assertEqual("=bar=", value, "key is not =bar=")

        # = in the key and value, with escaped escape character in both
        key, value = Secret._split_kv("\=foo\\\\=\=bar_\\\\_hi")
        self.assertEqual("=foo\\\\", key, "key is not =foo=")
        self.assertEqual("=bar_\\\\_hi", value, "key is not =bar=")

        try:
            Secret._split_kv("bad")
            self.fail("The key/value of 'bad' should have failed.")
        except Exception as err:
            self.assertRegex(str(err), r'The key/value format is invalid', 'did not get correct error message')
