import unittest
from unittest.mock import patch
import warnings
from click.testing import CliRunner
from keeper_secrets_manager_core.core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_cli.secret import Secret
from keeper_secrets_manager_cli.profile import Profile
from keeper_secrets_manager_cli.__main__ import cli
import tempfile
import json
import re
import os
import base64
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

        self.delete_me = []

    def tearDown(self) -> None:
        os.chdir(self.orig_dir)

        for item in self.delete_me:
            if os.path.exists(item) is True:
                os.unlink(item)

    def _make_temp_file(self):

        tf = tempfile.NamedTemporaryFile(delete=False)
        tf_name = tf.name
        self.delete_me.append(tf_name)
        tf.close()
        return tf_name

    def test_list(self):

        """ Test getting a list if secret records
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

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

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        # JSON Output
        queue.add_response(res)
        # Text Output
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'list', '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret_list = json.load(fh)
                for record in secret_list:
                    self.assertEqual(fast_lookup[record["title"]], record["uid"], "Bad UID for record: {}".format(
                        record["uid"]))
                fh.close()

            # Text Output
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'list'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "rb") as fh:
                table = fh.read()
                self.assertIsNotNone(re.search(one.uid, table.decode(), flags=re.MULTILINE),
                                     "did not find UID in table")
                fh.close()

    def test_get(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

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

        queue = mock.ResponseQueue(client=secrets_manager)
        for test in range(0, 8):
            queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output to file
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'get', '-u', one.uid, '--json'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret = json.load(fh)
                self.assertEqual(one.uid, secret["uid"], "didn't get the correct uid for secret")
                fh.close()

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
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'get', '-u', one.uid], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "rb") as fh:
                table = fh.read()
                self.assertIsNotNone(re.search(one.uid, table.decode(), flags=re.MULTILINE),
                                     "did not find UID in table")
                fh.close()

            # Text Output w/ JQ to stdout (force results to array, then adjust jq to handle arrays)

            # The single record will be converted to an array, so the first JSONPath expression needs to
            # reference an array.

            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'get', '-u', one.uid,
                '--query', '[*].fields[*].type',
                '--force-array'
            ], catch_exceptions=True)
            data = json.loads(result.output)
            self.assertEqual(4, len(data), "found 4 rows")
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            # Query the login without removing quotes
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'get', '-u', one.uid,
                '-q', "$.fields[?(@.type=='login')].value[0]"
            ], catch_exceptions=True)
            data = result.output
            self.assertEqual('"My Login 1"', data, "did not find quoted login")
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            # Query the login removing quotes
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'get', '-u', one.uid,
                '-q', "$.fields[?(@.type=='login')].value[0]",
                '--raw'
            ], catch_exceptions=True)
            data = result.output
            self.assertEqual('My Login 1', data, "did not find non-quoted login")
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

    def test_get_dash_uid(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        # UID starts with a dash to see if will be treated as a UID or a argument. We want UID :)
        dash_uid = '-uDASH'

        res = mock.Response()
        one = res.add_record(title="My Record 1", uid=dash_uid)
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        # Profile init
        queue.add_response(res)
        # Secret get
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output to file

            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'get', '-u', one.uid, '--json'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret = json.load(fh)
                self.assertEqual(dash_uid, secret["uid"], "didn't get the correct uid for secret")
                fh.close()

    def test_get_list_field(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.field("url", [])
        one.custom_field("My Custom", "custom1")

        two = res.add_record(title="My Record 2")
        two.field("login", "My Login 2")
        two.field("password", "My Password 2")
        two.field("url", [])
        two.custom_field("My Custom", "custom2")

        three = res.add_record(title="My Record 3")
        three.field("login", "My Login 3")
        three.field("password", "My Password 3")
        three.field("url", [])
        three.custom_field("My Custom", "custom3")

        queue = mock.ResponseQueue(client=secrets_manager)
        for test in range(0, 3):
            queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            runner = CliRunner()

            # JSON Output to file
            tf_name = self._make_temp_file()
            result = runner.invoke(cli, ['-o', tf_name,
                                         'secret', 'get', '--title', two.title, '--json'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret = json.load(fh)
                self.assertEqual(two.uid, secret["uid"], "didn't get the correct uid for secret")
                fh.close()

            result = runner.invoke(cli, ['secret', 'get',
                                         '--title', two.title, '--field', 'My Custom'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")
            # The line feed are stderr to make console display more readable.
            # Doing a FIELD=$(ksm ...) results in only stdout being captured.
            # Depending on OS, Python version, buffering CR/LF could happend
            # before or after the field value.
            self.assertRegex(result.output, r"^\n*custom2\n*$", "didn't get the expected field value")

    def test_download(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        mock_content = "ABC123"

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        mocked_file = one.add_file("my.mp4", content=mock_content)

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        def mock_download_get(_):
            mock_res = Response()
            mock_res.status_code = 200
            mock_res.reason = "OK"
            mock_res._content = mocked_file.downloadable_content()
            return mock_res

        with patch('requests.get', side_effect=mock_download_get) as mock_get:
            with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                    as mock_client:
                mock_client.return_value = secrets_manager

                Profile.init(token='MY_TOKEN')

                tf_name = self._make_temp_file()
                runner = CliRunner()
                result = runner.invoke(cli, [
                    'secret', 'download', '-u', one.uid, '--name', 'my.mp4',
                    '--file-output', tf_name
                ], catch_exceptions=False)

                with open(tf_name, "rb") as fh:
                    the_content = fh.read()
                    self.assertEqual(0, result.exit_code, "the exit code was not 0")
                    self.assertEqual(mock_content, the_content.decode(), 'the downloaded file does not match')
                    fh.close()
            self.assertEqual(1, mock_get.call_count, "the mock get call count is not 1")

        with patch('requests.get', side_effect=mock_download_get) as mock_get:
            with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                    as mock_client:
                mock_client.return_value = secrets_manager

                Profile.init(token='MY_TOKEN')

                tf_name = self._make_temp_file()
                runner = CliRunner()
                result = runner.invoke(cli, [
                    'secret', 'download', '-u', one.uid, '--file-uid', mocked_file.uid,
                    '--file-output', tf_name
                ], catch_exceptions=False)

                with open(tf_name, "rb") as fh:
                    the_content = fh.read()
                    self.assertEqual(0, result.exit_code, "the exit code was not 0")
                    self.assertEqual(mock_content, the_content.decode(), 'the downloaded file does not match')
                    fh.close()
            self.assertEqual(1, mock_get.call_count, "the mock get call count is not 1")

    def test_notation(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("My Custom 1", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)
        queue.add_response(res)
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

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
            self.assertRegex(result.output, r'Error: Invalid format of Keeper notation', 'got bad parse error')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # Too many / parameters
            too_much_notation = f"keeper://{one.uid}/field/login/BAD"
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', too_much_notation], catch_exceptions=False)
            self.assertRegex(result.output, r'Error: Cannot find standard field', 'got bad parse error')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # Bad field
            notation = "keeper://{}/{}/{}".format(one.uid, "field", "im_a_bad_field")
            runner = CliRunner()
            result = runner.invoke(cli, ['secret', 'notation', notation], catch_exceptions=False)
            self.assertRegex(result.output, r'Cannot get ', 'got an error for bad field')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

    def test_notation_file(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        # This is a tiny 2x2 PNG image base64 encoded.
        tiny_png_base64 = \
            "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAAXNSR0IArs4c6QAAAMJlWElmTU0AKgAAAAgABwESAAMAAAABAAEAAAEa" \
            "AAUAAAABAAAAYgEbAAUAAAABAAAAagEoAAMAAAABAAIAAAExAAIAAAARAAAAcgEyAAIAAAAUAAAAhIdpAAQAAAABAAAAmAAAAAAAAABI" \
            "AAAAAQAAAEgAAAABUGl4ZWxtYXRvciAzLjkuOAAAMjAyMTowNzoyMiAxNDowNzo3NgAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAAqAD" \
            "AAQAAAABAAAAAgAAAAByx + BYAAAACXBIWXMAAAsTAAALEwEAmpwYAAADpmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbW" \
            "V0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Im" \
            "h0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD" \
            "0iIgogICAgICAgICAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZX" \
            "hpZj0iaHR0cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICAgICAgICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS" \
            "94YXAvMS4wLyI + CiAgICAgICAgIDx0aWZmOkNvbXByZXNzaW9uPjA8L3RpZmY6Q29tcHJlc3Npb24 + CiAgICAgICAgIDx0aWZmOl" \
            "Jlc29sdXRpb25Vbml0PjI8L3RpZmY6UmVzb2x1dGlvblVuaXQ + CiAgICAgICAgIDx0aWZmOlhSZXNvbHV0aW9uPjcyPC90aWZmOlhS" \
            "ZXNvbHV0aW9uPgogICAgICAgICA8dGlmZjpZUmVzb2x1dGlvbj43MjwvdGlmZjpZUmVzb2x1dGlvbj4KICAgICAgICAgPHRpZmY6T3Jp" \
            "ZW50YXRpb24 + MTwvdGlmZjpPcmllbnRhdGlvbj4KICAgICAgICAgPGV4aWY6UGl4ZWxYRGltZW5zaW9uPjI8L2V4aWY6UGl4ZWxYRG" \
            "ltZW5zaW9uPgogICAgICAgICA8ZXhpZjpDb2xvclNwYWNlPjE8L2V4aWY6Q29sb3JTcGFjZT4KICAgICAgICAgPGV4aWY6UGl4ZWxZRG" \
            "ltZW5zaW9uPjI8L2V4aWY6UGl4ZWxZRGltZW5zaW9uPgogICAgICAgICA8eG1wOkNyZWF0b3JUb29sPlBpeGVsbWF0b3IgMy45Ljg8L3" \
            "htcDpDcmVhdG9yVG9vbD4KICAgICAgICAgPHhtcDpNb2RpZnlEYXRlPjIwMjEtMDctMjJUMTQ6MDc6NzY8L3htcDpNb2RpZnlEYXRlPg" \
            "ogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KPKL2agAAABNJREFUCB1j / M8gy8DAwATE" \
            "QAAADlwBIHTDGBYAAAAASUVORK5CYII ="

        file_res = mock.Response()
        file_record = file_res.add_record(title="My File 1", record_type='file')
        mocked_file_1 = file_record.add_file(
            name="Tiny Png",
            content=base64.b64decode(tiny_png_base64),
            content_type="image/png"
        )
        mocked_file_2 = file_record.add_file(
            name="my_text.txt",
            content="My Text",
            content_type="plain/text"
        )

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(file_res)
        queue.add_response(file_res)
        queue.add_response(file_res)
        queue.add_response(file_res)

        lookup = {
            mocked_file_1.uid: mocked_file_1,
            mocked_file_2.uid: mocked_file_2
        }

        def mock_download_get(url):
            uid = url.replace("http://localhost/", "")
            mock_res = Response()
            mock_res.status_code = 200
            mock_res.reason = "OK"
            mock_res._content = lookup[uid].downloadable_content()
            mock_res.headers["Content-Type"] = lookup[uid].content_type
            return mock_res

        with patch('requests.get', side_effect=mock_download_get) as _:
            with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                    as mock_client:
                mock_client.return_value = secrets_manager

                Profile.init(token='MY_TOKEN')

                # Write png to file. This will be binary data.
                tf_name = self._make_temp_file()
                notation = "keeper://{}/{}/{}".format(file_record.uid, "file", "Tiny Png")
                runner = CliRunner()
                result = runner.invoke(cli, [
                    "-o", tf_name,
                    'secret', 'notation', notation
                ], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")

                with open(tf_name, "rb") as fh:
                    self.assertEqual(fh.read(4), b"\x89PNG", "did not get a PNG")
                    fh.close()

                # Write plain text to file. This should not be binary data.
                tf_name = self._make_temp_file()
                notation = "keeper://{}/{}/{}".format(file_record.uid, "file", "my_text.txt")
                runner = CliRunner()
                result = runner.invoke(cli, [
                    "-o", tf_name,
                    'secret', 'notation', notation
                ], catch_exceptions=False)
                self.assertEqual(0, result.exit_code, "the exit code was not 0")

                with open(tf_name, "rb") as fh:
                    data = fh.read()
                    # TODO: I hate this. Plain text comes back a binary from mock since it's not going
                    #  threw a response handler.
                    self.assertEqual(b'My Text', data, "did not get my text file")
                    fh.close()

                # TODO: Need to capture to stdout. Can do it, however there is a charset encoding problem.
                #  The saved file looks like "<89>PNG^M" in the first line if saved. We need to emulated it. Stuff
                #  like "?PNG" or "�PNG" or "\ufffdPNG" are bad. :(

    def test_update(self):
        """Test updating an existing record
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")
        one.custom_field("my_custom", "custom1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        # The good one
        queue.add_response(res)
        queue.add_response(mock.Response(content="", status_code=200))

        # The bad field
        queue.add_response(res)

        # Bad server response
        queue.add_response(res)
        queue.add_response(mock.Response(content="I hate you and your little dog.", status_code=500))

        # JSON
        queue.add_response(res)
        queue.add_response(mock.Response(content="", status_code=200))

        # JSON Bad
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

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
            self.assertRegex(result.output, r'Could not save record', 'did not get correct error message for save')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

            # JSON
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field-json', "'login={\"One\":1}'",
                '--custom-field-json', "my_custom=[{\"Two\":2}]",
            ], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 1")

            # JSON Bad
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field-json', "'login=[{\"Bad One\":1}'",
                '--custom-field-json', "my_custom=[{\"Two\":2}]",
            ], catch_exceptions=False)
            self.assertRegex(result.output, r'The value is not valid JSON for',
                             'did not get correct error message for save')
            self.assertEqual(1, result.exit_code, "the exit code was not 1")

    def test_update_blank_labels(self):
        """Test updating an existing record
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response()
        one = res.add_record(title="My Record 1")
        one.field("login", label="", value="My Login 1")
        one.field("password", label="", value="My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(res)

        # The good one
        queue.add_response(res)
        queue.add_response(mock.Response(content="", status_code=200))

        # The bad field
        queue.add_response(res)

        # Bad server response
        queue.add_response(res)
        queue.add_response(mock.Response(content="I hate you and your little dog.", status_code=500))

        # JSON
        queue.add_response(res)
        queue.add_response(mock.Response(content="", status_code=200))

        # JSON Bad
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # Because of click/testing.py:278 ResourceWarning: unclosed file <_io.FileIO ...
            warnings.simplefilter("ignore", ResourceWarning)

            # The good one!
            runner = CliRunner()
            result = runner.invoke(cli, [
                'secret', 'update', '-u', one.uid,
                '--field', '"login=New Login"',
            ], catch_exceptions=False)
            print(result.output)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

    def test_kv_split(self):
        """Test splitting the key/value pairs
        """

        # The simple
        key, value = Secret._split_kv("foo=bar", is_json=False, labels=[r"foo"])
        self.assertEqual("foo", key, "key is not foo")
        self.assertEqual("bar", value, "value is not bar")

        # = in the key
        key, value = Secret._split_kv(r"=foo==bar", is_json=False, labels=[r"=foo="])
        self.assertEqual("=foo=", key, "key is not =foo=")
        self.assertEqual("bar", value, "value is not bar, the 2nd")

        # = in the key and value
        key, value = Secret._split_kv(r"=foo===bar=", is_json=False, labels=[r"=foo="])
        self.assertEqual("=foo=", key, "key is not =foo=")
        self.assertEqual("=bar=", value, "value is not =bar=")

        # = in the key and value, with escaped escape character in key
        key, value = Secret._split_kv(r"=foo\\==bar=", is_json=False, labels=[r"=foo\\"])
        self.assertEqual(r"=foo\\", key, "key is not =foo\\\\")
        self.assertEqual("=bar=", value, "value is not =bar=")

        # = in the key and value, with escaped escape character in both
        key, value = Secret._split_kv(r"=foo\\==bar_\\_hi", is_json=False, labels=[r"=foo\\"])
        self.assertEqual(r"=foo\\", key, "key is not =foo\\\\")
        self.assertEqual(r"=bar_\\_hi", value, "value is not =bar=")

        # Customer report test. Assign base64 value.
        key, value = Secret._split_kv("tls_cert=--BEGIN--abcdef==--END--", is_json=False, labels=[r"tls_cert"])
        self.assertEqual("tls_cert", key, "key is not tls_cert")
        self.assertEqual("--BEGIN--abcdef==--END--", value, "value is not base64 string")

        # Customer report test. Assign base64 value. Single quoted text.
        key, value = Secret._split_kv(r"'tls_cert=--BEGIN--abcdef==--END--'", is_json=False, labels=[r"tls_cert"])
        self.assertEqual("tls_cert", key, "key is not tls_cert")
        self.assertEqual("--BEGIN--abcdef==--END--", value, "value is not base64 string")

        # Customer report test. Assign base64 value. Double quoted text.
        key, value = Secret._split_kv("\"tls_cert=--BEGIN--abcdef==--END--\"", is_json=False, labels=[r"tls_cert"])
        self.assertEqual("tls_cert", key, "key is not tls_cert")
        self.assertEqual("--BEGIN--abcdef==--END--", value, "value is not base64 string")

        # Customer report test. Assign base64 value. Double quoted text abd quoted value.
        key, value = Secret._split_kv("\"tls_cert=\"QUOTE\"\"", is_json=False, labels=[r"tls_cert"])
        self.assertEqual("tls_cert", key, "key is not tls_cert")
        self.assertEqual("\"QUOTE\"", value, "value is not \"QUOTE\"")

        try:
            Secret._split_kv("bad=1", is_json=False, labels=[r"good"])
            self.fail("Cannot find the field/custom_field")
        except Exception as err:
            self.assertRegex(str(err), r'Cannot find the field/custom_field', 'did not get correct error message')

        # JSON Object test
        key, value = Secret._split_kv("json={\"One\":1}", is_json=True, labels=[r"json"])
        self.assertEqual("json", key, "key is not tls_cert")
        self.assertEqual([{'One': 1}], value, "value is not JSON")

        # JSON List test
        key, value = Secret._split_kv("json=[{\"One\":1}]", is_json=True, labels=[r"json"])
        self.assertEqual("json", key, "key is not tls_cert")
        self.assertEqual([{'One': 1}], value, "value is not JSON")

    def test_secrets_manager_record(self):

        """ Test how Secrets Manager stores record. Not custom fields, not 'custom' key in the response JSON.
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        res = mock.Response(flags={
            "prune_custom_fields": True
        })

        one = res.add_record(title="My Record 1")
        one.field("login", "My Login 1")
        one.field("password", "My Password 1")

        queue = mock.ResponseQueue(client=secrets_manager)
        # The profile init
        queue.add_response(res)
        # The secret get
        queue.add_response(res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, [
                '-o', tf_name,
                'secret', 'get', '-u', one.uid, '--json'], catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret = json.load(fh)
                self.assertEqual(dict, type(secret), "record is not a dictionary")
                self.assertEqual(0, len(secret["custom_fields"]), "custom fields were not empty")
                fh.close()

    def test_get_with_replacement(self):

        """This test will replace the addressRef with an actual address
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        profile_init_res = mock.Response()
        profile_init_res.add_record(title="Profile Init")

        address_res = mock.Response()
        address_record = address_res.add_record(title="My Record 1", record_type="address")
        address_record.field("address", [
            {
                "street1": "100 North Main Street",
                "street2": "Suite 1000",
                "city": "Middletown",
                "state": "WI",
                "zip": "53074",
                "country": "US"
            }
        ])

        login_res = mock.Response()
        login_record = login_res.add_record(title="My Record 1", record_type="login")
        login_record.custom_field("My Address", [address_record.uid], field_type='addressRef')

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(profile_init_res)
        queue.add_response(login_res)
        queue.add_response(address_res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output to file
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'get', '-u', login_record.uid, '--json'],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "r") as fh:
                secret = json.load(fh)
                self.assertEqual(login_record.uid, secret["uid"], "didn't get the correct uid for secret")

                address = secret["custom_fields"][0]
                self.assertEqual(dict, type(address), "address value is not a dict")
                self.assertEqual("My Address", address["label"], "did not get the addressRef")

                fh.close()

    def test_totp(self):

        """Test TOTP
        """

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        profile_init_res = mock.Response()
        profile_init_res.add_record(title="Profile Init")

        totp_res = mock.Response()
        totp_record = totp_res.add_record(title="My Record 1", record_type="address")
        totp_record.field("oneTimeCode", [
            "otpauth://totp/ACME:jw@localhost?secret=MYSECRET&issuer=ACME&algorithm=SHA1&digits=6&period=30"
        ], label='oneTimeCode')

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(profile_init_res)
        queue.add_response(totp_res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            # JSON Output to file
            tf_name = self._make_temp_file()
            runner = CliRunner()
            result = runner.invoke(cli, ['-o', tf_name, 'secret', 'totp', totp_record.uid],
                                   catch_exceptions=False)
            self.assertEqual(0, result.exit_code, "the exit code was not 0")

            with open(tf_name, "rb") as fh:
                code = fh.readline()
                code = code.decode()
                self.assertEqual(6, len(code), "code is not 6 character long")
                self.assertRegex(code, r'^\d{6}$', 'code is not all digits')
                fh.close()

    def test_generate_password(self):

        """Generate a password
        """

        #  Default values
        tf_name = self._make_temp_file()
        runner = CliRunner()
        result = runner.invoke(cli, ['-o', tf_name, 'secret', 'password'],
                               catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "the exit code was not 0")

        with open(tf_name, "rb") as fh:
            password = fh.readline().decode()
            self.assertEqual(len(password), 64, "Default password is not 64 characters.")

            fh.close()

        #  Set the length to 32
        tf_name = self._make_temp_file()
        runner = CliRunner()
        result = runner.invoke(cli, ['-o', tf_name, 'secret', 'password', '--length', '32'],
                               catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "the exit code was not 0")

        with open(tf_name, "rb") as fh:
            password = fh.readline().decode()
            self.assertEqual(len(password), 32, "Default password is not 64 characters.")

            fh.close()

        #  Set character groups
        tf_name = self._make_temp_file()
        runner = CliRunner()
        result = runner.invoke(cli, ['-o', tf_name, 'secret', 'password',
                                     '-lc', '4',
                                     '-uc', '5',
                                     '-d', '6',
                                     '-sc', '7'],
                               catch_exceptions=False)
        self.assertEqual(0, result.exit_code, "the exit code was not 0")

        with open(tf_name, "rb") as fh:
            password = fh.readline().decode()
            self.assertEqual(len(password), 22, "Default password is not 64 characters.")

            fh.close()

        #  Bad
        tf_name = self._make_temp_file()
        runner = CliRunner()
        result = runner.invoke(cli, ['-o', tf_name, 'secret', 'password',
                                     '-l', '100',
                                     '-lc', '4',
                                     '-uc', '5',
                                     '-d', '6',
                                     '-sc', '7'],
                               catch_exceptions=False)
        self.assertEqual(1, result.exit_code, "the exit code was not 1")

    def test_template_record_types(self):

        """Test the template record type command
        """

        # Get a list of record types, display to terminal
        runner = CliRunner()
        results = runner.invoke(cli, ['secret', 'template', 'record', '-l'], catch_exceptions=False)
        output = results.output
        self.assertRegex(output, r'Record Type', 'Did not find the table title')
        self.assertRegex(output, r'login', 'found the login record type')

        # Get a record type as JSON and write it to a file
        tf_name = self._make_temp_file()
        runner = CliRunner()
        runner.invoke(cli, ['secret', 'template', 'record', '-f', tf_name, 'login'], catch_exceptions=False)

        with open(tf_name, "rb") as fh:
            schema = json.loads(fh.read().decode())
            self.assertEqual("v3", schema.get("version"), "did not get the correct version")
            self.assertEqual("KeeperRecord", schema.get("kind"), "did not get the correct kind")
            self.assertIsInstance(schema.get("data"), list, "data is not a list")

            data = schema.get("data")[0]

            self.assertEqual("login", data.get("recordType"), "record type is not login")
            self.assertIsNotNone(data.get("title"), "title was None")
            self.assertIsNotNone(data.get("notes"), "title was None")

            self.assertIsInstance(data.get("fields"), list, "fields is not a list")

            field = data.get("fields")[1]
            self.assertEqual("login", field.get("type"), "field type is not login")
            self.assertIsNotNone(field.get("value"), "value was None")

            fh.close()

    def test_template_field_types(self):

        """Test the template field type command
        """

        # Get a list of record types, display to terminal
        runner = CliRunner()
        results = runner.invoke(cli, ['secret', 'template', 'field', '-l'], catch_exceptions=False)
        output = results.output
        self.assertRegex(output, r'Field Type', 'Did not find the table title')
        self.assertRegex(output, r'accountNumber', 'found the accountNumber field type')

        # Get a record type as JSON and write it to a file
        runner = CliRunner()
        results = runner.invoke(cli, ['secret', 'template', 'field', 'securityQuestion'],
                                catch_exceptions=False)
        output = results.output
        schema = json.loads(output)

        self.assertEqual("securityQuestion", schema.get("type"), "field type is not securityQuestion")
        self.assertIsNotNone(schema.get("value"), "value was None")

    def test_add_record_via_field(self):

        mock_config = MockConfig.make_config()
        secrets_manager = SecretsManager(config=InMemoryKeyValueStorage(mock_config))

        profile_init_res = mock.Response()
        profile_init_res.add_folder(uid="FAKEUID")
        profile_init_res.add_record(title="Profile Init")

        queue = mock.ResponseQueue(client=secrets_manager)
        queue.add_response(profile_init_res)
        queue.add_response(profile_init_res)
        queue.add_response(profile_init_res)

        with patch('keeper_secrets_manager_cli.KeeperCli.get_client') \
                as mock_client:
            mock_client.return_value = secrets_manager

            Profile.init(token='MY_TOKEN')

            runner = CliRunner()
            results = runner.invoke(cli, ['secret', 'add', 'field',
                                          '--sf', 'FAKEUID',
                                          '--rt', 'login',
                                          '--title', 'My Title',
                                          '-p',
                                          'login=jsmith',
                                          'url=http://localhost'
                                          ], catch_exceptions=False)
            output = results.output
            # stderr and stdout are merged:
            # Depending on OS, Python version, buffering CR/LF could happend
            # before or after the expected value.
            # 'UIDxxxxxxxxxxxxxxxxxxxThe following is the new record UID..' or
            # 'The following is the new record UID..\nUIDxxxxxxxxxxxxxxxxxxx\n'
            prefix = "The following is the new record UID ..."
            lines = [line for line in
                     (line.replace(prefix, "").strip()
                      for line in output.split("\n")) if line]
            self.assertTrue(lines, "did not get back a record uid")  # empty
            self.assertRegex(lines[0], r'^[\w_-]{22}$', "did not get back a record uid")


if __name__ == '__main__':
    unittest.main()
