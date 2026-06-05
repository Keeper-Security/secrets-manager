# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2024 Keeper Security Inc.
# Contact: sm@keepersecurity.com

"""KSM-877 — throttle retry with exponential backoff.

The backend throttles with HTTP 403 {"error":"throttled"}; the SDK retries inside the
``_post_query`` loop with exponential backoff + jitter (see ``MAX_THROTTLE_RETRIES`` /
``BASE_THROTTLE_DELAY_SEC``) and raises ``KeeperThrottleError`` once retries are exhausted.

``time.sleep`` is patched in every test so the suite never actually waits, and
``random.uniform`` is patched where a deterministic delay value is asserted.
"""

import json
import logging
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from requests import HTTPError

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError, KeeperThrottleError
from keeper_secrets_manager_core.keeper_globals import (
    BASE_THROTTLE_DELAY_SEC,
    MAX_THROTTLE_RETRIES,
    logger_name,
)
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage

# Patch targets — core.py does ``import random`` / ``import time``.
SLEEP = "keeper_secrets_manager_core.core.time.sleep"
UNIFORM = "keeper_secrets_manager_core.core.random.uniform"


def make_sm():
    return SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))


def throttled_response(retry_after=None):
    """A canned HTTP 403 throttle response (optionally carrying retry_after)."""
    body = {"error": "throttled", "message": "throttled"}
    if retry_after is not None:
        body["retry_after"] = retry_after
    return mock.Response(content=json.dumps(body).encode(), status_code=403)


def record_response(title="My Record"):
    """A normal 200 response containing a single record."""
    res = mock.Response()
    rec = res.add_record(title=title)
    rec.field("login", "My Login")
    rec.field("password", "My Password")
    return res


class ThrottleDelayUnitTest(unittest.TestCase):
    """Pure-function coverage of the delay computation and throttle detection."""

    def _delay_no_jitter(self, attempt, retry_after=0.0):
        with patch(UNIFORM, return_value=0.0):
            return SecretsManager._throttle_delay(attempt, retry_after)

    def test_exponential_sequence(self):
        delays = [self._delay_no_jitter(n, 0.0) for n in range(MAX_THROTTLE_RETRIES)]
        self.assertEqual(delays, [11, 22, 44, 88, 176])

    def test_retry_after_precedence(self):
        # A positive retry_after wins over the exponential value (88 for attempt 3).
        self.assertEqual(self._delay_no_jitter(3, 7.0), 7)

    def test_retry_after_nonpositive_ignored(self):
        self.assertEqual(self._delay_no_jitter(0, 0.0), 11)
        self.assertEqual(self._delay_no_jitter(1, -5.0), 22)

    def test_jitter_upper_bound(self):
        with patch(UNIFORM, return_value=0.25):
            self.assertAlmostEqual(SecretsManager._throttle_delay(0, 0.0), 13.75)

    def test_jitter_lower_bound(self):
        with patch(UNIFORM, return_value=-0.25):
            self.assertAlmostEqual(SecretsManager._throttle_delay(0, 0.0), 8.25)

    def test_jitter_within_bounds_real_random(self):
        base = BASE_THROTTLE_DELAY_SEC * (2 ** 2)  # attempt 2 -> 44
        for _ in range(1000):
            delay = SecretsManager._throttle_delay(2, 0.0)
            self.assertGreaterEqual(delay, base * 0.75)
            self.assertLessEqual(delay, base * 1.25)

    def test_parse_throttle_no_retry_after(self):
        r = SimpleNamespace(text=json.dumps({"error": "throttled"}))
        self.assertEqual(SecretsManager._parse_throttle(r), 0.0)

    def test_parse_throttle_with_retry_after(self):
        r = SimpleNamespace(text=json.dumps({"error": "throttled", "retry_after": 5}))
        self.assertEqual(SecretsManager._parse_throttle(r), 5.0)

    def test_parse_throttle_result_code_key(self):
        # handler_http_error reads result_code before error; _parse_throttle mirrors that.
        r = SimpleNamespace(text=json.dumps({"result_code": "throttled"}))
        self.assertEqual(SecretsManager._parse_throttle(r), 0.0)

    def test_parse_throttle_other_error_is_none(self):
        r = SimpleNamespace(text=json.dumps({"error": "access_denied"}))
        self.assertIsNone(SecretsManager._parse_throttle(r))

    def test_parse_throttle_non_json_is_none(self):
        self.assertIsNone(SecretsManager._parse_throttle(SimpleNamespace(text="Bad Gateway")))

    def test_parse_throttle_empty_is_none(self):
        self.assertIsNone(SecretsManager._parse_throttle(SimpleNamespace(text="")))
        self.assertIsNone(SecretsManager._parse_throttle(SimpleNamespace(text=None)))

    def test_parse_throttle_bad_retry_after(self):
        r = SimpleNamespace(text=json.dumps({"error": "throttled", "retry_after": "soon"}))
        self.assertEqual(SecretsManager._parse_throttle(r), 0.0)


class ThrottleRetryIntegrationTest(unittest.TestCase):
    """End-to-end coverage through the public API, driving the real _post_query loop."""

    def setUp(self):
        self.orig_working_dir = os.getcwd()

    def tearDown(self):
        os.chdir(self.orig_working_dir)

    @patch(SLEEP)
    def test_retry_then_success(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(throttled_response())
        q.add_response(record_response())

        records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        self.assertEqual(mock_sleep.call_count, 1)

    @patch(UNIFORM, return_value=0.0)
    @patch(SLEEP)
    def test_multiple_throttles_then_success(self, mock_sleep, _uniform):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(throttled_response())
        q.add_response(throttled_response())
        q.add_response(record_response())

        records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        delays = [c.args[0] for c in mock_sleep.call_args_list]
        self.assertEqual(delays, [11, 22])  # exponential, jitter pinned to 0

    @patch(SLEEP)
    def test_retry_exhausted_raises(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        for _ in range(MAX_THROTTLE_RETRIES + 1):
            q.add_response(throttled_response())

        with self.assertRaises(KeeperThrottleError) as ctx:
            sm.get_secrets()

        # Subclasses KeeperError, so legacy handlers still catch it.
        self.assertIsInstance(ctx.exception, KeeperError)
        self.assertEqual(mock_sleep.call_count, MAX_THROTTLE_RETRIES)

    @patch(UNIFORM, return_value=0.0)
    @patch(SLEEP)
    def test_retry_after_honored(self, mock_sleep, _uniform):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(throttled_response(retry_after=2))
        q.add_response(record_response())

        records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        mock_sleep.assert_called_once_with(2)

    @patch(SLEEP)
    def test_retry_on_write_path(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(record_response())  # initial get to obtain a record
        record = sm.get_secrets()[0]

        q.add_response(throttled_response())       # save() throttled once
        q.add_response(mock.Response(content=""))  # then succeeds
        sm.save(record)

        self.assertEqual(mock_sleep.call_count, 1)

    @patch(SLEEP)
    def test_throttle_and_key_rotation_compose(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(throttled_response())
        q.add_response(mock.Response(
            content=json.dumps({"error": "key", "key_id": "2"}).encode(), status_code=403))
        q.add_response(record_response())

        records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        # Key rotation still applied (unaffected by the throttle path)...
        self.assertEqual(sm.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), "2")
        # ...and only the throttle slept; key rotation does not consume throttle budget.
        self.assertEqual(mock_sleep.call_count, 1)

    @patch(SLEEP)
    def test_non_throttle_403_not_retried(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        err = {"error": "access_denied", "message": "Signature is invalid"}
        q.add_response(mock.Response(content=json.dumps(err).encode(), status_code=403))

        with self.assertRaises(KeeperError):
            sm.get_secrets()
        mock_sleep.assert_not_called()

    @patch(SLEEP)
    def test_non_json_502_not_retried(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(mock.Response(content=b"Bad Gateway", status_code=502))

        with self.assertRaises(HTTPError):
            sm.get_secrets()
        mock_sleep.assert_not_called()

    @patch(SLEEP)
    def test_counter_resets_per_call(self, mock_sleep):
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        # Two independent calls, each throttled once then served.
        q.add_response(throttled_response())
        q.add_response(record_response())
        q.add_response(throttled_response())
        q.add_response(record_response())

        self.assertEqual(len(sm.get_secrets()), 1)
        self.assertEqual(len(sm.get_secrets()), 1)
        self.assertEqual(mock_sleep.call_count, 2)


class ThrottleLoggingTest(unittest.TestCase):
    """The retry path logs a WARNING with the attempt number and the delay."""

    @patch(SLEEP)
    def test_logs_warning_on_throttle(self, _mock_sleep):
        sm = SecretsManager(
            config=InMemoryKeyValueStorage(MockConfig.make_config()), log_level="WARNING")
        logging.getLogger(logger_name).disabled = False  # defensive (singleton logger)

        q = mock.ResponseQueue(client=sm)
        q.add_response(throttled_response())
        q.add_response(record_response())

        with self.assertLogs(logger_name, level="WARNING") as cm:
            records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        output = "\n".join(cm.output)
        self.assertIn("throttled", output.lower())
        self.assertRegex(output, r"attempt 1/%d" % MAX_THROTTLE_RETRIES)


class ThrottleLiveIntegrationTest(unittest.TestCase):
    """Optional live-backend smoke test (skipped unless KSM_INTEGRATION_CONFIG is set).

    A real throttle (HTTP 403 throttled) cannot be reliably forced in CI without abusively
    hammering the backend (>100 req/10s) or lowering the server-side ServerSettingDAO limit, so
    this only confirms the modified _post_query still works end-to-end against a live server.
    Provide a base64 KSM config via KSM_INTEGRATION_CONFIG to run it as a manual QA step.
    """

    @unittest.skipUnless(
        os.environ.get("KSM_INTEGRATION_CONFIG"),
        "set KSM_INTEGRATION_CONFIG (base64 KSM config) to run the live test")
    def test_live_get_secrets(self):
        sm = SecretsManager(
            config=InMemoryKeyValueStorage(os.environ["KSM_INTEGRATION_CONFIG"]))
        records = sm.get_secrets()
        self.assertIsInstance(records, list)


if __name__ == "__main__":
    unittest.main()
