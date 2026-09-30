# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2026 Keeper Security Inc.
# Contact: sm@keepersecurity.com

"""Bounded key-rotation retry (KSM-1069).

The server signals a public-key change with HTTP 403 {"error": "key", "key_id": N}.
Without a retry bound, the loop is infinite (handler_http_error returns True and
_post_query loops). With a pinned custom server key (IL5), the server will never
accept a standard key rotation, making the loop unbounded by design.

These tests verify:
  - _parse_key_rotation correctly identifies key-rotation responses
  - A single rotation resolves and the new key_id is stored
  - Repeated rotations raise KeeperError after MAX_KEY_ROTATION_RETRIES attempts
  - A pinned custom key raises KeeperError immediately on the first rotation response
"""

import json
import unittest
from types import SimpleNamespace

from keeper_secrets_manager_core import SecretsManager, mock
from keeper_secrets_manager_core.configkeys import ConfigKeys
from keeper_secrets_manager_core.exceptions import KeeperError
from keeper_secrets_manager_core.keeper_globals import MAX_KEY_ROTATION_RETRIES, keeper_public_keys
from keeper_secrets_manager_core.mock import MockConfig
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage


def make_sm():
    return SecretsManager(config=InMemoryKeyValueStorage(MockConfig.make_config()))


def key_response(key_id="8"):
    body = {"error": "key", "key_id": key_id}
    return mock.Response(content=json.dumps(body).encode(), status_code=403)


def record_response(title="My Record"):
    res = mock.Response()
    rec = res.add_record(title=title)
    rec.field("login", "My Login")
    rec.field("password", "My Password")
    return res


class KeyRotationUnitTest(unittest.TestCase):
    """Direct unit tests for SecretsManager._parse_key_rotation."""

    def _r(self, body):
        return SimpleNamespace(text=json.dumps(body) if body is not None else None)

    def test_parse_key_rotation_error_key(self):
        r = self._r({"error": "key", "key_id": "8"})
        self.assertEqual(SecretsManager._parse_key_rotation(r), "8")

    def test_parse_key_rotation_result_code_key(self):
        # handler_http_error reads result_code before error; _parse_key_rotation mirrors that.
        r = self._r({"result_code": "key", "key_id": "9"})
        self.assertEqual(SecretsManager._parse_key_rotation(r), "9")

    def test_parse_key_rotation_other_error(self):
        r = self._r({"error": "access_denied"})
        self.assertIsNone(SecretsManager._parse_key_rotation(r))

    def test_parse_key_rotation_non_json(self):
        self.assertIsNone(SecretsManager._parse_key_rotation(SimpleNamespace(text="Bad Gateway")))

    def test_parse_key_rotation_empty(self):
        self.assertIsNone(SecretsManager._parse_key_rotation(SimpleNamespace(text="")))
        self.assertIsNone(SecretsManager._parse_key_rotation(SimpleNamespace(text=None)))


class KeyRotationRetryTest(unittest.TestCase):
    """End-to-end coverage through the public API for the key-rotation retry path."""

    def test_key_rotation_single_then_success(self):
        # Server requests one key rotation, then serves the record normally.
        # Asserts: call succeeds and the new key_id is stored in config.
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        q.add_response(key_response("8"))
        q.add_response(record_response())

        records = sm.get_secrets()

        self.assertEqual(len(records), 1)
        self.assertEqual(sm.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID), "8")

    def test_key_rotation_exhausted_raises(self):
        # Server keeps requesting key rotation past the retry budget.
        # Asserts: KeeperError raised after exactly MAX_KEY_ROTATION_RETRIES retries.
        sm = make_sm()
        q = mock.ResponseQueue(client=sm)
        for _ in range(MAX_KEY_ROTATION_RETRIES + 1):
            q.add_response(key_response("8"))

        with self.assertRaises(KeeperError):
            sm.get_secrets()

    def test_key_rotation_with_custom_key_raises_immediately(self):
        # IL5 scenario: a custom server public key is pinned in config.
        # The server sends error='key'. The SDK must raise immediately; accepting a
        # standard key rotation would silently break the IL5 deployment.
        sm = make_sm()
        # Use a real EC P-256 public key so generate_transmission_key succeeds and the
        # request reaches the server. The guard fires on the server's key-rotation response.
        sm.config.set(ConfigKeys.KEY_SERVER_PUBLIC_KEY, keeper_public_keys['7'])
        q = mock.ResponseQueue(client=sm)
        q.add_response(key_response("8"))

        with self.assertRaises(KeeperError) as ctx:
            sm.get_secrets()

        self.assertIn("custom", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
