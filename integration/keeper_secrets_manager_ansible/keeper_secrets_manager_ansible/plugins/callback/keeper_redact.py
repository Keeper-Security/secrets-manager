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
        - 'Multiline values are learned as complete sequences rather than independent lines.'
        - 'It hides the keeper_config, keeper_config_file, keeper_client_id, keeper_private_key, keeper_app_key,
          keeper_token, and keeper_record_cache_secret variables when a task result shows them by name.'
        - 'It does not hide these variables when a task shows them under another name, for example in the msg of a
          debug or fail task. Use no_log: True on such tasks.'
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


def _line_sequences(text):
    # The command module strips trailing CR/LF characters before Ansible builds stdout_lines and stderr_lines.
    return {tuple(lines) for lines in (text.splitlines(), text.rstrip("\r\n").splitlines(), text.split("\n"))
            if len(lines) > 1}


def _sequence_prefix(lines):
    prefix = [0] * len(lines)
    matched = 0
    for index in range(1, len(lines)):
        while matched and lines[index] != lines[matched]:
            matched = prefix[matched - 1]
        if lines[index] == lines[matched]:
            matched += 1
        prefix[index] = matched
    return prefix


def _sequence_indices(values, sequences):
    protected = set()
    for lines, prefix in sequences.items():
        matched = covered = 0
        for index, value in enumerate(values):
            while matched and value != lines[matched]:
                matched = prefix[matched - 1]
            if value == lines[matched]:
                matched += 1
            if matched == len(lines):
                end = index + 1
                protected.update(range(max(end - matched, covered), end))
                covered = end
                matched = prefix[matched - 1]
    return protected


def _position_mask(indices):
    if len(indices) == 1:
        return 1 << indices[0]
    bits = bytearray((indices[-1] + 8) // 8)
    for position in indices:
        bits[position // 8] |= 1 << (position % 8)
    return int.from_bytes(bits, "little")


def _token_pattern(lines, token_lines, split_lines):
    aliases = {}
    ambiguous = False
    for line in lines:
        for token in token_lines[line][int(split_lines)]:
            ambiguous |= aliases.setdefault(token, line) != line
    if not ambiguous:
        return aliases, None, None, None
    positions = {}
    for index, line in enumerate(lines):
        for token in token_lines[line][int(split_lines)]:
            positions.setdefault(token, []).append(index)
    dense = {token: _position_mask(indices) for token, indices in positions.items()
             if (indices[-1] + 8) // 8 <= 4 * len(indices)}
    return None, positions, dense, {}


def _token_indices(values, sequences, prefixes, split_lines=False):
    protected = set()
    for lines, alternatives in sequences.items():
        if len(values) < len(lines):
            continue
        aliases, positions, dense, cache = alternatives[int(split_lines)]
        if aliases is not None:
            protected.update(_sequence_indices([aliases.get(value) for value in values], {lines: prefixes[lines]}))
            continue
        terminal = 1 << (len(lines) - 1)
        matched = covered = 0
        for index, value in enumerate(values):
            # Keep every possible prefix when quoted representations share a spelling.
            mask = dense.get(value)
            if mask is None:
                mask = cache.pop(value, None)
                if mask is None:
                    indices = positions.get(value)
                    mask = _position_mask(indices) if indices else 0
                if mask:
                    # Keep sparse positions and bound the least-recently-used wide masks.
                    if len(cache) >= 16:
                        del cache[next(iter(cache))]
                    cache[value] = mask
            matched = ((matched << 1) | 1) & mask
            if matched & terminal:
                end = index + 1
                protected.update(range(max(end - len(lines), covered), end))
                covered = end
    return protected


def _string_runs(text, token_values):
    # Scan complete containers without evaluating or rewriting the surrounding text.
    tokens = []
    quotes = {}
    previous_quotes = {}
    words = {}
    cursor = 0
    punctuation = "\"'[](){},:"
    while cursor < len(text):
        char = text[cursor]
        if char in " \t\r\n":
            cursor += 1
            continue
        start = cursor
        if char in punctuation:
            tokens.append((char, start, start + 1))
            if char in "\"'":
                previous = previous_quotes.get(char)
                if previous is not None:
                    quotes[previous] = len(tokens)
                previous_quotes[char] = len(tokens) - 1
            cursor += 1
            continue
        while cursor < len(text):
            char = text[cursor]
            if char in punctuation or char in " \t\r\n":
                break
            cursor += 2 if char == "\\" else 1
        tokens.append(("", start, min(cursor, len(text))))
        if cursor - start <= 6:
            word = text[start:cursor]
            if word in ("or", "and", "if", "else", "lambda", "+", "|"):
                words[len(tokens) - 1] = word

    # Link each element and delimiter tail once to recover from prose without rescanning.
    elements = {}
    containers = {}
    tails = {}
    mappings = {}
    conditions = {}
    parameters = {}
    endings = {"[": "]", "(": ")", "{": "}"}
    for index in range(len(tokens) - 1, -1, -1):
        char, start, end = tokens[index]
        if char in ("]", ")", "}"):
            tails[index] = (char, index + 1)
            if char == "}":
                mappings[index] = index + 1
            continue
        if char == ":" and index + 1 in elements:
            parameters[index] = elements[index + 1]
        elif char in ('"', "'"):
            after = quotes.get(index)
            if after in parameters:
                parameters[index] = parameters[after]
        elif not char:
            after = index + 1
            if after < len(tokens) and tokens[after][0] == ",":
                after += 1
            if after in parameters:
                parameters[index] = parameters[after]
        following = None
        if char in ('"', "'"):
            following = quotes.get(index)
        elif not char:
            following = index + 1
            if index + 1 < len(tokens):
                next_char, next_start, _next_end = tokens[index + 1]
                if end - start == 1 and text[start] in "bB" and next_start == end and next_char in ('"', "'"):
                    following = elements.get(index + 1)
                elif next_char in ("(", "["):
                    following = elements.get(index + 1)
            if words.get(index) == "lambda":
                following = parameters.get(index + 1)
        elif char in endings:
            tail = tails.get(index + 1)
            if tail is not None and tail[0] == endings[char]:
                following = tail[1]
            if char == "{":
                following = mappings.get(index + 1, following)
            if following is not None:
                containers[index] = following
        if following is None:
            continue
        if following < len(tokens) and tokens[following][0] in ("(", "["):
            following = elements.get(following)
        if following is None:
            continue
        operation = words.get(following)
        if operation in ("or", "and", "+", "|"):
            following = elements.get(following + 1)
        elif operation == "if":
            following = conditions.get(following + 1)
        if following is None:
            continue
        elements[index] = following
        if following >= len(tokens):
            continue
        next_char = tokens[following][0]
        if words.get(following) == "else" and following + 1 in elements:
            conditions[index] = elements[following + 1]
        if next_char in ("]", ")", "}"):
            tails[index] = (next_char, following + 1)
        elif next_char == ",":
            tail = tails.get(following + 1)
            if tail is not None:
                tails[index] = tail
        if next_char == ":":
            value_end = elements.get(following + 1)
            if value_end is not None and value_end < len(tokens):
                separator = tokens[value_end][0]
                if separator == "}":
                    mappings[index] = value_end + 1
                elif separator == "," and value_end + 1 in mappings:
                    mappings[index] = mappings[value_end + 1]
    tails.clear()
    mappings.clear()
    words.clear()
    conditions.clear()
    parameters.clear()

    # Each quote kind divides the token stream into nonoverlapping intervals.
    quote_containers = {}
    quote_limits = {'"': 0, "'": 0}
    for index in range(len(tokens) - 1, -1, -1):
        char = tokens[index][0]
        if char in quote_limits:
            if quote_limits[char]:
                quote_containers[index] = quote_limits[char]
            quote_limits[char] = 0
        limit = containers.get(index, 0)
        if limit:
            quote_limits['"'] = max(quote_limits['"'], limit)
            quote_limits["'"] = max(quote_limits["'"], limit)

    stack = []
    runs = []
    index = 0
    previous = ""
    previous_end = 0
    callable_end = False
    indexable_end = False
    root_quote_end = None

    def finish(frame):
        if frame["tokens"]:
            runs.append(frame["tokens"])
            frame["tokens"] = []

    # Root quotes may belong to prose. Only complete containers establish string opacity.
    while index < len(tokens):
        char, start, end = tokens[index]
        frame = stack[-1] if stack else None
        binary = (not char and end - start == 1 and text[start] in "bB" and index + 1 < len(tokens)
                  and tokens[index + 1][0] in ('"', "'") and tokens[index + 1][1] == end)
        if char in ('"', "'") or binary:
            quote_index = index + int(binary)
            following = quotes.get(quote_index)
            recovered = False
            if frame is not None and frame["root_quote"] and following is not None and \
                    quote_containers.get(quote_index, 0) > frame["limit"] + 1:
                stack.clear()
                frame = None
                recovered = True
            if frame is None:
                root_quote_end = None if recovered else \
                    following - 1 if following is not None else len(tokens)
            if frame is not None and following is not None:
                quote_at = start + int(binary)
                last = tokens[following - 1][1]
                if frame["strings"] and frame["value"]:
                    token = text[start:last + 1]
                    complete = following == frame["limit"] or \
                        following < len(tokens) and tokens[following][0] == ","
                    if complete and token in token_values:
                        frame["tokens"].append((token, quote_at + 1, last))
                    else:
                        finish(frame)
                frame["value"] = False
                frame["root_quote"] = False
                previous = tokens[index + int(binary)][0]
                previous_end = last + 1
                callable_end = False
                indexable_end = False
                index = following
                continue
        elif char in endings and index in containers:
            blocked = bool(frame and (frame["blocked"] or (frame["end"] == "}" and not frame["value"])))
            if frame is not None:
                finish(frame)
                frame["value"] = False
            call = char == "(" and callable_end
            # Track callable indexing separately from printed array items.
            indexed = char == "[" and indexable_end
            strings = char != "{" and not blocked and not call and not (indexed and previous_end == start)
            # An opener in root quotation is provisional until a complete item is consumed.
            root_quote = frame is None and root_quote_end is not None and index < root_quote_end
            stack.append({"end": endings[char], "limit": containers[index] - 1, "root_quote": root_quote,
                          "strings": strings,
                          "blocked": blocked, "indexed": indexed, "value": char != "{", "tokens": []})
        elif frame is not None:
            if index == frame["limit"]:
                finish(stack.pop())
                previous = char
                previous_end = end
                callable_end = char == ")" or frame["indexed"]
                indexable_end = True
                index += 1
                continue
            elif char == ",":
                frame["value"] = frame["end"] != "}"
            elif char == ":":
                frame["value"] = frame["end"] == "}"
            elif not char:
                finish(frame)
                frame["value"] = False
        previous = char or text[end - 1]
        previous_end = end
        callable_end = previous.isalnum() or previous in "._"
        indexable_end = callable_end
        index += 1
    return runs


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
        self._forms = set()
        self._array_forms = set()
        self._sequences = {}
        self._token_sequences = {}
        self._token_values = set()
        self._split_token_values = set()
        self._token_lines = {}

    def _learn(self, action, body):
        key = self.SECRET_RESULT_KEYS.get(action)
        if key is None:
            return
        items = [body]
        if isinstance(body.get("results"), list):
            items += [item for item in body["results"] if isinstance(item, Mapping)]
        for item in items:
            # Learn complete and normalized forms.
            values = []
            complete = set()
            for leaf in _leaves(item.get(key)):
                values.extend([leaf, leaf.rstrip("\r\n")])
                if len(leaf) >= self.MIN_MATCH_LENGTH:
                    # Retain complete multiline forms when normalization crosses the match floor.
                    trimmed = leaf.rstrip("\r\n")
                    if len(trimmed.splitlines()) > 1:
                        complete.add(trimmed)
                    normalized = leaf.replace("\r\n", "\n").replace("\r", "\n")
                    for form in (normalized, normalized.rstrip("\r\n")):
                        if len(form.splitlines()) > 1:
                            values.append(form)
                            complete.add(form)
                            crlf = form.replace("\n", "\r\n")
                            values.append(crlf)
                            complete.add(crlf)
                    for sequence in _line_sequences(leaf):
                        lines = list(sequence)
                        normalized = "\n".join(lines)
                        values.append(normalized)
                        if len(normalized.splitlines()) > 1:
                            complete.add(normalized)
            for leaf in values:
                if (len(leaf) >= self.MIN_MATCH_LENGTH or leaf in complete) and leaf not in self._learned:
                    self._learned.add(leaf)
                    for lines in _line_sequences(leaf):
                        if lines not in self._sequences:
                            self._sequences[lines] = _sequence_prefix(lines)
                            for line in lines:
                                if line not in self._token_lines:
                                    tokens = {repr(line), ascii(line), json.dumps(line),
                                              json.dumps(line, ensure_ascii=False)}
                                    try:
                                        tokens.add(repr(line.encode("utf-8", "surrogateescape")))
                                    except UnicodeEncodeError:
                                        pass
                                    split_tokens = tokens | {"\n".join(token.splitlines()) for token in tokens}
                                    self._token_lines[line] = (tokens, split_tokens)
                                    self._token_values.update(tokens)
                                    self._split_token_values.update(split_tokens)
                            self._token_sequences[lines] = tuple(
                                _token_pattern(lines, self._token_lines, split_lines) for split_lines in (False, True))
                        values_list = list(lines)
                        self._array_forms.update({repr(values_list), json.dumps(values_list),
                                                  json.dumps(values_list, ensure_ascii=False)})
                    # Each secret appears in output as itself, as JSON text (ensure_ascii on and off), and inside
                    # the quotes of a Python text or bytes repr, which exception messages use.
                    self._forms.update({leaf, json.dumps(leaf)[1:-1], json.dumps(leaf, ensure_ascii=False)[1:-1],
                                        repr(leaf)[1:-1]})
                    # Reverse attachment decoding, including surrogateescaped text from older Ansible versions.
                    try:
                        data = leaf.encode("utf-8", "surrogateescape")
                    except UnicodeEncodeError:
                        # A text value with a lone surrogate has no UTF-8 digest. Its text forms still need masking.
                        continue
                    self._forms.add(repr(data)[2:-1])
                    # The built-in copy module returns the SHA-1 of its content, and a hash of a short secret can be
                    # found by guessing. Hide the common digests of each secret too.
                    for name in ("sha1", "md5", "sha256"):
                        try:
                            self._forms.add(hashlib.new(name, data, usedforsecurity=False).hexdigest())
                        except ValueError:
                            # An unavailable digest must not stop masking or callback dispatch.
                            pass

    def _serialized_spans(self, text, split_lines=False):
        spans = set()
        if self._sequences:
            tokens = self._split_token_values if split_lines else self._token_values
            for run in _string_runs(text, tokens):
                protected = _token_indices([token[0] for token in run], self._token_sequences,
                                           self._sequences, split_lines)
                spans.update((run[index][1], run[index][2]) for index in protected)
        return spans

    def _literal_spans(self, text):
        spans = set()
        for forms in (self._forms, self._array_forms):
            for form in forms:
                start = text.find(form)
                while start != -1:
                    spans.add((start, start + len(form)))
                    start = text.find(form, start + 1)
        return spans

    def _redact_text(self, text, extra_spans=(), serialized=True):
        if text in self._array_forms:
            return REDACTED
        # Find every match first, then merge overlaps. Replacing one secret at a time leaves the tail of a secret
        # that overlaps another, and a replacement can create a new match.
        spans = self._serialized_spans(text) if serialized else set()
        spans.update(extra_spans)
        spans.update(self._literal_spans(text))
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

    def _redact_lines(self, obj):
        text = [bytes(item).decode("utf-8", "surrogateescape") if isinstance(item, (bytes, bytearray))
                else item if isinstance(item, str) else None for item in obj]
        protected = _sequence_indices(text, self._sequences)
        serialized = {}
        start = 0
        while self._sequences and start < len(text):
            if text[start] is None:
                start += 1
                continue
            end = start + 1
            while end < len(text) and text[end] is not None:
                end += 1
            # Keep the complete chunk's string context and literal spans when projecting physical entries.
            joined = "\n".join(text[start:end])
            offsets = []
            position = 0
            for value in text[start:end]:
                offsets.append((position, position + len(value)))
                position += len(value) + 1
            item = 0
            spans = self._serialized_spans(joined, split_lines=True)
            spans.update(self._literal_spans(joined))
            for left, right in sorted(spans):
                while item + 1 < len(offsets) and offsets[item][1] < left:
                    item += 1
                current = item
                while current < len(offsets) and offsets[current][0] <= right:
                    lower, upper = offsets[current]
                    first, last = max(left, lower), min(right, upper)
                    if first < last or left == right and first == last:
                        serialized.setdefault(start + current, []).append((first - lower, last - lower))
                    if upper >= right:
                        break
                    current += 1
            start = end
        return [REDACTED if index in protected else
                self._redact_text(text[index], serialized.get(index, ()), serialized=False) if text[index] is not None else
                self._redact(item) for index, item in enumerate(obj)]

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
            return self._redact_lines(obj)
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
