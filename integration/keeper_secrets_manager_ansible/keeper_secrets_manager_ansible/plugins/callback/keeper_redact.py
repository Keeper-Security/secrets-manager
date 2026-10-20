# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

DOCUMENTATION = '''
    name: keeper_redact
    type: stdout
    short_description: Redact Keeper secrets from task results
    version_added: historical
    description:
        - This output callback hides the values that keeper_get, keeper_get_record, and keeper_password return.
        - 'It also hides values of four or more characters when later tasks in the same run print them.'
        - 'This output callback will not hide secret values from a lookup. Use no_log: True to hide the output.'
        - 'This output callback changes only what it prints. It does not change registered results or other callbacks.'
        - 'This output callback does not hide secrets from AWX and AAP job events. Use no_log: True.'
        - 'AWX and AAP set their own stdout callback, so a stdout_callback setting in ansible.cfg does not load this callback there.'
    extends_documentation_fragment:
      - default_callback
    requirements:
      - set as stdout in configuration
'''

from ansible.plugins.callback.default import CallbackModule as DefaultCallbackBase
from collections.abc import Mapping
import hashlib
import json

REDACTED = "****"


def _result_body(result):
    # ansible-core 2.19 and later name the public attributes. Earlier versions have only the underscore ones.
    return result.result if hasattr(result, "result") else result._result


def _result_action(result):
    task = result.task if hasattr(result, "task") else result._task
    return str(getattr(task, "resolved_action", None) or task.action).rsplit(".", 1)[-1]


def _leaves(obj):
    if isinstance(obj, (bytes, bytearray)):
        obj = bytes(obj).decode("utf-8", "surrogateescape")
    if isinstance(obj, str):
        return [obj] if obj else []
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        return [str(obj)]
    if isinstance(obj, Mapping):
        return [leaf for value in obj.values() for leaf in _leaves(value)]
    if isinstance(obj, (list, tuple)):
        return [leaf for item in obj for leaf in _leaves(item)]
    return []


class CallbackModule(DefaultCallbackBase):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'keeper_redact'

    KEEPER_KEYS = [
        "keeper_config",
        "keeper_config_file",
        "keeper_client_id",
        "keeper_private_key",
        "keeper_app_key",
        "keeper_token",
        "keeper_record_cache_secret",
    ]

    # The key of each Keeper action result that holds secret values.
    # Keep this table. Do not pass secret values to this callback in the task result.
    # The actions run in worker processes, so the task result is the only data that reaches this callback.
    # A task result also goes to registered variables and to other callbacks.
    # ansible-core 2.15 to 2.20 also remove internal keys before a callback receives the result.
    SECRET_RESULT_KEYS = {
        "keeper_get": "value",
        "keeper_get_record": "record",
        "keeper_password": "password",
    }

    # A secret shorter than this is hidden only in the result of the Keeper action that returned it. Searching other
    # output for it would also hide ordinary words and numbers.
    MIN_MATCH_LENGTH = 4

    def __init__(self):
        super(CallbackModule, self).__init__()
        # Secret values from this run. They stay in this process and must never reach a log line, a repr, or a file.
        self._learned = set()
        self._forms = []

    def _learn(self, action, body):
        key = self.SECRET_RESULT_KEYS.get(action)
        if key is None:
            return
        items = [body]
        if isinstance(body.get("results"), list):
            items += [item for item in body["results"] if isinstance(item, Mapping)]
        for item in items:
            for leaf in _leaves(item.get(key)):
                if len(leaf) >= self.MIN_MATCH_LENGTH and leaf not in self._learned:
                    self._learned.add(leaf)
                    # Reverse attachment decoding, including surrogateescaped text from older Ansible versions.
                    data = leaf.encode("utf-8", "surrogateescape")
                    # Each secret appears in output as itself, as JSON text (ensure_ascii on and off), and inside
                    # the quotes of a Python text or bytes repr, which exception messages use.
                    self._forms.extend({leaf, json.dumps(leaf)[1:-1], json.dumps(leaf, ensure_ascii=False)[1:-1],
                                        repr(leaf)[1:-1], repr(data)[2:-1]} - set(self._forms))
                    # The built-in copy module returns the SHA-1 of its content, and a hash of a short secret can be
                    # found by guessing. Hide the common digests of each secret too.
                    self._forms.extend(hashlib.new(name, data).hexdigest()
                                       for name in ("sha1", "md5", "sha256"))

    def _redact_text(self, text):
        # Find every match first, then merge overlaps. Replacing one secret at a time leaves the tail of a secret
        # that overlaps another, and a replacement can create a new match.
        spans = []
        for form in self._forms:
            start = text.find(form)
            while start != -1:
                spans.append((start, start + len(form)))
                start = text.find(form, start + 1)
        if not spans:
            return text
        parts = []
        position = 0
        for start, end in sorted(spans):
            if start >= position:
                parts.append(text[position:start])
                parts.append(REDACTED)
                position = end
            elif end > position:
                position = end
        parts.append(text[position:])
        return "".join(parts)

    def _redact(self, obj, payload_key=None):
        if isinstance(obj, str):
            return self._redact_text(obj)
        if isinstance(obj, (bytes, bytearray)):
            return self._redact_text(bytes(obj).decode("utf-8", "surrogateescape"))
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            return REDACTED if str(obj) in self._learned else obj
        if isinstance(obj, Mapping):
            clean = {}
            for key, value in obj.items():
                # Identify sensitive settings and secret payloads before their keys become redacted display names.
                if key in self.KEEPER_KEYS:
                    value = REDACTED
                elif payload_key is not None and key == payload_key:
                    value = self._mask(value)
                name = self._redact_text(key) if isinstance(key, str) else key
                # Two keys can become the same text. Keep both values.
                suffix = 1
                unique = name
                while unique in clean:
                    suffix += 1
                    unique = "{}_{}".format(name, suffix)
                if payload_key is not None and key == "results" and isinstance(value, list):
                    clean[unique] = [self._redact(item, payload_key=payload_key) for item in value]
                else:
                    clean[unique] = self._redact(value)
            return clean
        if isinstance(obj, (list, tuple)):
            return [self._redact(item) for item in obj]
        return obj

    def _mask(self, obj):
        if isinstance(obj, Mapping):
            return {key: self._mask(value) for key, value in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._mask(item) for item in obj]
        return REDACTED if _leaves(obj) else obj

    def _scrub(self, result):
        body = _result_body(result)
        if not isinstance(body, dict):
            return
        action = _result_action(result)
        self._learn(action, body)

        # Rebuild the result instead of editing it. Nested objects in the original can be shared with the registered
        # variable and with other callbacks.
        clean = self._redact(body, payload_key=self.SECRET_RESULT_KEYS.get(action))

        # ansible-core 2.19 and later print the error from an object on the result, not from the dictionary, so the
        # copy above cannot hide it. Take the error marker out of the copy and print the redacted message instead.
        shown_error = getattr(result, "exception", None) is not None and bool(clean.pop("exception", None))

        body.clear()
        body.update(clean)
        if shown_error:
            message = clean.get("msg")
            self._display.error("Task failed: {}".format(message) if isinstance(message, str) else "Task failed.")


def _scrubbing(name):
    def hook(self, result, *args, **kwargs):
        self._scrub(result)
        return getattr(super(CallbackModule, self), name)(result, *args, **kwargs)
    hook.__name__ = name
    return hook


for _name in ("v2_runner_on_ok", "v2_runner_on_failed", "v2_runner_on_unreachable", "v2_runner_on_skipped",
              "v2_runner_item_on_ok", "v2_runner_item_on_failed", "v2_runner_item_on_skipped", "v2_runner_retry",
              "v2_on_file_diff", "v2_runner_on_async_ok", "v2_runner_on_async_failed"):
    setattr(CallbackModule, _name, _scrubbing(_name))
