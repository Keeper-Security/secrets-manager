import os
import re
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

from keeper_secrets_manager_core import mock
from keeper_secrets_manager_core.core import KSMCache

from keeper_secrets_manager_ansible import KeeperAnsible, KeeperFieldType

# Passwords that make the request library reject the proxy URL and echo it. "p@ss" and "100%25" still parse, so
# they never reach the error path here. The scrubber is checked against them directly.
PROXY_PASSWORDS = ("S3c#ret", "p/ss", "a#b/c@d%e")

# The SDK picks a route per operation. With the cache, get_secret goes to custom_post_function. Every other
# route, and get_secret without the cache, goes to client.post_function, which is the credential-hiding wrapper.
GET_SECRET_ROUTE = ("get_secret route", lambda keeper: keeper.get_records_from_vault(uids=["UID1"]))
POST_FUNCTION_ROUTE = ("post_function route", lambda keeper: keeper.get_folders())
ROUTES = (GET_SECRET_ROUTE, POST_FUNCTION_ROUTE)


def _full_text(error):
    """The message plus the whole traceback chain, which is what -vvv prints."""
    return str(error) + "".join(traceback.format_exception(type(error), error, error.__traceback__))


class KeeperProxyRedactTest(unittest.TestCase):
    """A proxy credential must not reach the task message or the -vvv output when a request fails."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ksm_cache.bin"
        self.config = mock.MockConfig.make_base64()
        self.verbose = []
        for started in (patch.object(KSMCache, "kms_cache_file_name", str(self.path)),
                        patch.dict(os.environ, {"KSM_CACHE_DIR": self.directory.name}),
                        patch("keeper_secrets_manager_ansible.display.warning"),
                        patch("keeper_secrets_manager_ansible.display.vvv",
                              side_effect=lambda text, *a, **k: self.verbose.append(str(text)))):
            started.start()
            self.addCleanup(started.stop)
        # A NO_PROXY of * or an ALL_PROXY in the caller's shell sends the request around the proxy, so the
        # leak tests would pass without the fix. patch.dict above restores the environment afterwards.
        for name in list(os.environ):
            if name.lower() in ("no_proxy", "all_proxy"):
                del os.environ[name]

    def _keeper(self, proxy, use_cache=False):
        task_vars = {"keeper_config": self.config}
        if use_cache:
            task_vars["keeper_use_cache"] = True
        with patch.dict(os.environ, {"https_proxy": proxy, "HTTPS_PROXY": proxy}):
            return KeeperAnsible(task_vars=task_vars)

    def _fail(self, keeper, proxy, operation):
        with patch.dict(os.environ, {"https_proxy": proxy, "HTTPS_PROXY": proxy}):
            with self.assertRaises(Exception) as context:
                operation(keeper)
        return context.exception

    def test_the_proxy_password_stays_out_of_the_traceback_on_both_routes(self):
        # -vvv prints the whole chain, so the original error must not hang on as __cause__ or __context__.
        for password in PROXY_PASSWORDS:
            for route, operation in ROUTES:
                with self.subTest(password=password, route=route):
                    proxy = "http://alice:{}@127.0.0.1:9".format(password)
                    error = self._fail(self._keeper(proxy), proxy, operation)
                    self.assertNotIn(password, _full_text(error))

    def test_the_cache_fallback_does_not_log_the_proxy_password(self):
        for password in PROXY_PASSWORDS:
            with self.subTest(password=password):
                self.verbose.clear()
                self.path.write_bytes(b"c" * 32 + b"cached response")
                proxy = "http://alice:{}@127.0.0.1:9".format(password)
                keeper = self._keeper(proxy, use_cache=True)
                self.verbose.clear()
                # The cached bytes are not a valid response. Only the log line from the fallback matters here.
                self._fail(keeper, proxy, GET_SECRET_ROUTE[1])
                self.assertTrue([line for line in self.verbose if "The request to the Keeper server failed" in line],
                                "the fallback did not run, so the test checks nothing")
                self.assertNotIn(password, "\n".join(self.verbose))

    def test_the_proxy_password_stays_out_of_a_file_download_error(self):
        # The SDK downloads a file with its own requests call, not with post_function, so a wrapper on the vault
        # transport does not cover it. Both plugin entry points reach that call: a file field and keeper:// notation.
        entry_points = (
            ("file field", lambda keeper, uid: keeper.get_value(KeeperFieldType.FILE, "My File", uid=uid)),
            ("file notation", lambda keeper, uid: keeper.get_value_via_notation("{}/file/My File".format(uid))),
        )
        for password in PROXY_PASSWORDS:
            for entry_point, operation in entry_points:
                with self.subTest(password=password, entry_point=entry_point):
                    proxy = "http://alice:{}@127.0.0.1:9".format(password)
                    keeper = self._keeper(proxy)
                    response = mock.Response()
                    record = mock.Record(title="Record 1", record_type="login")
                    record.add_file(name="My File", title="My File", url="https://files.test/f")
                    response.add_record(record=record)
                    queue = mock.ResponseQueue(client=keeper.client)
                    queue.add_response(response)
                    # The vault read returns the record from the queue. Only the file download uses the proxy.
                    keeper.client.custom_post_function = queue.post_method
                    error = self._fail(keeper, proxy, lambda k: operation(k, record.uid))
                    self.assertNotIn(password, _full_text(error))


class RemoveProxyCredentialsTest(unittest.TestCase):
    """remove_proxy_credentials(text, proxy_url=None) strips URL userinfo and keeps scheme, host and port."""

    SCRUB_PASSWORDS = ("S3c#ret", "p/ss", "p@ss", "100%25", "a#b/c@d%e")

    def _rows(self):
        """Yield (name, proxy_url, text, secrets, kept) for each case."""
        for password in self.SCRUB_PASSWORDS:
            url = "http://alice:{}@127.0.0.1:9".format(password)
            forms = (
                ("parse error", "Failed to parse: {}".format(url)),
                ("proxy error", "HTTPSConnectionPool(host='vault.test', port=443): Max retries exceeded with url: "
                                "/api (Caused by ProxyError('Cannot connect to proxy.', OSError('{}')))".format(url)),
                ("embedded", "Cannot get record: the proxy {} refused the request, see the log".format(url)),
                ("twice", "first {} then again {}".format(url, url)),
            )
            for form, text in forms:
                # With the exact value configured, and with no value, where only the regex fallback can work.
                yield "{} {} exact".format(password, form), url, text, ("alice", password), "http://127.0.0.1:9"
                yield "{} {} regex only".format(password, form), None, text, ("alice", password), "http://127.0.0.1:9"
        yield ("user only", "http://alice@127.0.0.1:9", "Failed to parse: http://alice@127.0.0.1:9", ("alice",),
               "http://127.0.0.1:9")
        yield ("user only, regex only", None, "Failed to parse: http://alice@127.0.0.1:9", ("alice",),
               "http://127.0.0.1:9")
        # A URL that differs from the configured proxy, so the exact replacement cannot match it.
        yield ("other url", "http://alice:S3c#ret@127.0.0.1:9",
               "Failed to parse: http://bob:Zz9#q@10.0.0.5:3128", ("bob", "Zz9#q"), "http://10.0.0.5:3128")

    def test_userinfo_is_removed_and_the_host_and_port_stay(self):
        from keeper_secrets_manager_ansible import remove_proxy_credentials

        for name, proxy_url, text, secrets, kept in self._rows():
            with self.subTest(case=name):
                result = remove_proxy_credentials(text, proxy_url)
                for secret in secrets:
                    self.assertNotIn(secret, result)
                # One scrubbed URL stays for each URL in the input, so the message is not emptied.
                self.assertEqual(result.count(kept), len(re.findall(r"@(?:127\.0\.0\.1:9|10\.0\.0\.5:3128)", text)))
                self.assertNotEqual(result.strip(), "")

    def test_text_without_userinfo_is_unchanged(self):
        from keeper_secrets_manager_ansible import remove_proxy_credentials

        for text in ("Connection refused by the host", "Failed to parse: http://127.0.0.1:9",
                     "https://vault.test/api/rest/sm/v1/get_secret returned 500"):
            for proxy_url in (None, "http://alice:S3c#ret@127.0.0.1:9"):
                with self.subTest(text=text, proxy_url=proxy_url):
                    self.assertEqual(remove_proxy_credentials(text, proxy_url), text)


PROXY_VARIABLES = ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")


class KeeperUnparsableUrlTest(unittest.TestCase):
    """The proxy message is for a proxy that is configured. Another bad URL must not blame the proxy."""

    def setUp(self):
        self.config = mock.MockConfig.make_base64()
        for started in (patch.dict(os.environ, {}), patch("keeper_secrets_manager_ansible.display.vvv")):
            started.start()
            self.addCleanup(started.stop)
        # requests reads these names in any letter case, so a developer shell with Https_Proxy or HTTP_PROXY set
        # would change the result. patch.dict above restores the environment afterwards.
        for name in list(os.environ):
            if name.lower() in ("https_proxy", "http_proxy", "all_proxy", "no_proxy") or name == "KSM_HOSTNAME":
                del os.environ[name]

    def _fail(self, operation, keeper=None):
        keeper = keeper or KeeperAnsible(task_vars={"keeper_config": self.config})
        with self.assertRaises(Exception) as context:
            operation(keeper)
        return context.exception

    @staticmethod
    def _file_download(keeper):
        response = mock.Response()
        record = mock.Record(title="Record 1", record_type="login")
        record.add_file(name="My File", title="My File", url="https://files.test:abc/f")
        response.add_record(record=record)
        queue = mock.ResponseQueue(client=keeper.client)
        queue.add_response(response)
        keeper.client.custom_post_function = queue.post_method
        return keeper.get_value(KeeperFieldType.FILE, "My File", uid=record.uid)

    def test_a_bad_keeper_url_does_not_blame_the_proxy(self):
        # The SDK reads the server from KSM_HOSTNAME before the config. A non-numeric port cannot be parsed.
        for proxy in (None, "http://alice:hunter2@127.0.0.1:9"):
            with self.subTest(proxy=proxy):
                if proxy is not None:
                    os.environ["https_proxy"] = proxy
                os.environ["KSM_HOSTNAME"] = "vault.test:abc"
                error = self._fail(lambda k: k.get_folders())
                self.assertIn("vault.test", str(error))
                self.assertNotIn("proxy", str(error).lower())
                self.assertNotIn("hunter2", _full_text(error))
                os.environ.pop("https_proxy", None)

    def test_a_bad_file_url_does_not_blame_the_proxy(self):
        for proxy in (None, "http://alice:hunter2@127.0.0.1:9"):
            with self.subTest(proxy=proxy):
                if proxy is not None:
                    os.environ["https_proxy"] = proxy
                error = self._fail(self._file_download, KeeperAnsible(task_vars={"keeper_config": self.config}))
                # A real file URL is a presigned link that works for anyone who holds it, so the message must not
                # echo it.
                self.assertIn("file", str(error).lower())
                self.assertNotIn("files.test", str(error))
                self.assertNotIn("proxy", str(error).lower())
                self.assertNotIn("hunter2", _full_text(error))
                os.environ.pop("https_proxy", None)

    def test_a_bad_keeper_url_with_a_user_name_and_password_does_not_echo_them(self):
        # The message names the host the user set. A host written as user:password@host must lose the user part.
        os.environ["KSM_HOSTNAME"] = "alice:hunter2@vault.test:abc"
        error = self._fail(lambda k: k.get_folders())
        self.assertIn("vault.test", str(error))
        self.assertNotIn("hunter2", _full_text(error))
        self.assertNotIn("alice", _full_text(error))

    def test_a_proxy_in_all_proxy_is_hidden_and_the_message_names_only_that_variable(self):
        os.environ["ALL_PROXY"] = "http://alice:S3c#ret@127.0.0.1:9"
        error = self._fail(lambda k: k.get_folders())
        self.assertNotIn("S3c#ret", _full_text(error))
        self.assertIn("ALL_PROXY", str(error))
        self.assertNotIn("https_proxy", str(error))

    def test_a_proxy_in_a_mixed_case_variable_is_hidden(self):
        # requests reads Https_Proxy, so the plugin cannot match the variable by an exact name.
        os.environ["Https_Proxy"] = 'http://alice:S3c#r"t@127.0.0.1:9'
        error = self._fail(lambda k: k.get_folders())
        self.assertNotIn('S3c#r"t', _full_text(error))
        self.assertIn("Percent-encode", str(error))


# The euro sign is outside latin-1, so the request library cannot put it in the Proxy-Authorization header.
# Written as an escape so that no tool has to carry the character.
NON_LATIN1_PASSWORD = "p\u20acw"
NON_LATIN1_PROXIES = (
    ("raw", "http://alice:p\u20acw@127.0.0.1:9"),
    # The request library decodes the percent escapes before it encodes the header, so this fails the same way.
    ("percent-encoded", "http://alice:p%E2%82%ACw@127.0.0.1:9"),
)


def _chain_text(error):
    """str, repr and traceback text of the error and of every error that the traceback shows as its cause."""
    parts, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        parts += [str(error), repr(error), _full_text(error)]
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return "\n".join(parts)


class KeeperNonLatin1ProxyPasswordTest(unittest.TestCase):
    """A proxy password outside latin-1 makes the request layer raise UnicodeEncodeError, and its repr holds it."""

    def setUp(self):
        self.config = mock.MockConfig.make_base64()
        for started in (patch.dict(os.environ, {}), patch("keeper_secrets_manager_ansible.display.vvv")):
            started.start()
            self.addCleanup(started.stop)
        for name in list(os.environ):
            if name.lower() in ("no_proxy", "all_proxy", "https_proxy", "http_proxy") or name == "KSM_HOSTNAME":
                del os.environ[name]

    def _fail(self, operation, proxy):
        os.environ["https_proxy"] = proxy
        keeper = KeeperAnsible(task_vars={"keeper_config": self.config})
        with self.assertRaises(Exception) as context:
            operation(keeper)
        return context.exception

    @staticmethod
    def _file_download(keeper):
        response = mock.Response()
        record = mock.Record(title="Record 1", record_type="login")
        record.add_file(name="My File", title="My File", url="https://files.test/f")
        response.add_record(record=record)
        queue = mock.ResponseQueue(client=keeper.client)
        queue.add_response(response)
        keeper.client.custom_post_function = queue.post_method
        return keeper.get_value(KeeperFieldType.FILE, "My File", uid=record.uid)

    def test_a_password_outside_latin1_stays_out_of_str_repr_and_traceback_on_both_routes(self):
        routes = (("post_function route", lambda k: k.get_folders()), ("file download", self._file_download))
        for form, proxy in NON_LATIN1_PROXIES:
            for route, operation in routes:
                with self.subTest(form=form, route=route):
                    text = _chain_text(self._fail(operation, proxy))
                    self.assertNotIn(NON_LATIN1_PASSWORD, text)
                    self.assertNotIn("\u20ac", text)
                    self.assertNotIn("p%E2%82%ACw", text)

    def test_the_message_names_the_cause_and_does_not_advise_percent_encoding(self):
        # Percent-encoding does not help here, so the percent-encoding advice of the unparsable-URL message is wrong.
        for route, operation in (("post_function route", lambda k: k.get_folders()),
                                 ("file download", self._file_download)):
            with self.subTest(route=route):
                message = str(self._fail(operation, NON_LATIN1_PROXIES[0][1])).lower()
                self.assertIn("latin-1", message)
                self.assertIn("proxy user name or password", message)
                self.assertNotIn("percent", message)

    def test_an_encoding_error_without_a_matching_proxy_is_raised_unchanged(self):
        # Guards the fix against catching every UnicodeEncodeError. The proxy credential here encodes as latin-1,
        # so the error comes from somewhere else and the original object is the useful one.
        os.environ["https_proxy"] = "http://alice:p\u00e9w@127.0.0.1:9"
        original = UnicodeEncodeError("latin-1", "x\u20acy", 1, 2, "ordinal not in range(256)")
        with patch("keeper_secrets_manager_core.SecretsManager.post_function", side_effect=original):
            with self.assertRaises(UnicodeEncodeError) as context:
                KeeperAnsible._transport("https://vault.test", None, b"", True, None)
        self.assertIs(context.exception, original)
