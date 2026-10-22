import ast
import copy
import hashlib
import itertools
import json
import random
import re
import shutil
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from keeper_secrets_manager_core import mock
from .ansible_test_framework import AnsibleTestFramework


MASK = "****"
PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END RSA PRIVATE KEY-----"
KNOWN_PEM = PEM_HEADER + "\nSYNTHETIC_ALPHA_8092\n" + PEM_FOOTER
FOREIGN_PEM = PEM_HEADER + "\nSYNTHETIC_BETA_9082\n" + PEM_FOOTER
RAW_LINE_SEPARATORS = ("\n", "\r\n", "\r", "\u0085", "\u2028", "\u2029", "\v", "\f", "\x1c", "\x1d", "\x1e")


def _callback(*secrets):
    from keeper_secrets_manager_ansible.plugins.callback.keeper_redact import CallbackModule

    callback = CallbackModule()
    for secret in secrets:
        callback._learn("keeper_get", {"value": secret})
    return callback


ENCODERS = [
    pytest.param(json.dumps, json.loads, id="json"),
    pytest.param(lambda value: json.dumps(value, separators=(",", ":")), json.loads, id="compact-json"),
    pytest.param(lambda value: json.dumps(value, indent=4), json.loads, id="pretty-json"),
    pytest.param(lambda value: json.dumps(value, ensure_ascii=False), json.loads, id="unicode-json"),
    pytest.param(lambda value: json.dumps(value, ensure_ascii=False, indent=7), json.loads, id="pretty-unicode-json"),
    pytest.param(repr, ast.literal_eval, id="repr"),
    pytest.param(ascii, ast.literal_eval, id="ascii"),
]

CAPTIONS = [
    "User's result: ",
    "Operator's log: ",
    "Job [user's info]: ",
    "Message {user's info}: ",
    "(User's result): ",
    "[User's result] ",
    "(Bob's output): ",
    "[Bob's output] ",
    'Report "user": ',
    "Unclosed ' caption: ",
    'Unclosed " caption: ',
    *["Invalid key " + quote + label + quote + ": "
      for quote in ("'", '"') for delimiter in "[](){}"
      for label in (delimiter, "name " + delimiter, delimiter + " name", "name " + delimiter + " label")],
]


@pytest.mark.parametrize("secret,public", [
    ("user: bob\n    \npass: synthetic-8092!\n", json.dumps({"a": {"b": 1}}, indent=4)),
    ("root\nenabled\ntrue", "service root is enabled and true"),
    ("root\nenabled\ntrue", {"root": "enabled", "status": "true"}),
    ("root\nenabled\ntrue", [{"isolated": "root"}, {"isolated": "enabled"}, {"isolated": "true"}]),
    (KNOWN_PEM, FOREIGN_PEM),
])
def test_multiline_values_do_not_learn_independent_public_fragments(secret, public):
    callback = _callback(secret)
    original = copy.deepcopy(public)
    assert callback._redact(public) == public
    assert public == original


@pytest.mark.parametrize("separator", RAW_LINE_SEPARATORS)
@pytest.mark.parametrize("split", [str.splitlines, lambda value: value.split("\n")])
@pytest.mark.parametrize("kind", [str, bytes, bytearray])
@pytest.mark.parametrize("prefix", ["", "public-prefix ", "public-prefix\nbefore: "])
@pytest.mark.parametrize("suffix", ["", " public-suffix", "\npublic-suffix"])
def test_complete_raw_literals_project_into_physical_entries_with_public_surroundings(separator, split, kind, prefix,
                                                                                    suffix):
    first, last = "FIRST_PRIVATE_8092", "LAST_PRIVATE_9082"
    secret = first + separator + last
    callback = _callback(secret)
    text = prefix + secret + suffix
    physical = split(text)
    if kind is not str:
        physical = [kind(value.encode("utf-8")) for value in physical]
    original = copy.deepcopy(physical)
    shown = callback._redact(physical)
    rendered = "\n".join(shown)
    assert first not in rendered and last not in rendered
    assert rendered.startswith(prefix) and rendered.endswith(suffix)
    assert len(shown) == len(physical) and MASK in rendered
    assert callback._redact_text(text) == prefix + MASK + suffix
    assert physical == original


@pytest.mark.parametrize("separator", RAW_LINE_SEPARATORS)
@pytest.mark.parametrize("kind", [str, bytes, bytearray])
@pytest.mark.parametrize("body", [
    pytest.param(lambda first, last: ["before public", last + " suffix"], id="missing-first"),
    pytest.param(lambda first, last: ["prefix " + first, "public after"], id="missing-last"),
    pytest.param(lambda first, last: ["prefix " + first, "gap", last + " suffix"], id="gap"),
    pytest.param(lambda first, last: ["prefix " + first, None, last + " suffix"], id="none"),
    pytest.param(lambda first, last: ["prefix " + first, 17, last + " suffix"], id="number"),
    pytest.param(lambda first, last: ["prefix " + first, {"public": "gap"}, last + " suffix"], id="mapping"),
    pytest.param(lambda first, last: ["prefix " + first, ["gap"], last + " suffix"], id="nested"),
    pytest.param(lambda first, last: ["prefix " + first + " and " + last + " suffix"], id="ordinary-words"),
])
def test_raw_literal_projection_does_not_match_fragments_gaps_or_nontext_barriers(separator, kind, body):
    first, last = "FIRST_PRIVATE_8092", "LAST_PRIVATE_9082"
    callback = _callback(first + separator + last)
    values = body(first, last)
    expected = copy.deepcopy(values)
    if kind is not str:
        values = [kind(value.encode("utf-8")) if isinstance(value, str) else value for value in values]
    original = copy.deepcopy(values)
    assert callback._redact(values) == expected
    assert values == original


def test_an_independently_fetched_scalar_still_masks_later_output():
    callback = _callback("root\nenabled\ntrue", "enabled")
    assert callback._redact("service root is enabled and true") == "service root is **** and true"
    assert callback._redact({"root": "enabled", "status": "true"}) == {"root": MASK, "status": "true"}


def _shape(name, values):
    return {"flat": values, "nested": [values], "mapping": {"data": values}, "tuple": (values,)}[name]


@pytest.mark.parametrize("secret", [
    "first-private-line\nlast-private-line",
    "root\nenabled\ntrue",
    "first-8092\nx\nlast-9082\n",
    "first-8092\n\nlast-9082",
    "x\ny\n",
    "ab\r\ncd\r\n",
    'quoted"first\\8092\nsingle\'second-9082',
    "euro-\u20ac-first-8092\nlast-\u6f22-9082",
    "first-8092\udcff\nlast-9082\ud800",
])
@pytest.mark.parametrize("shape", ["flat", "nested", "mapping", "tuple"])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_complete_serialized_sequences_preserve_surrounding_structure(secret, shape, encode, decode):
    callback = _callback(secret)
    lines = secret.splitlines()
    body = _shape(shape, ["public-before"] + lines + ["public-after"])
    expected = _shape(shape, ["public-before"] + [MASK] * len(lines) + ["public-after"])
    before, after = "public-prefix ", " public-suffix"
    shown = callback._redact_text(before + encode(body) + after)
    assert shown.startswith(before) and shown.endswith(after)
    assert decode(shown[len(before):-len(after)]) == decode(encode(expected))


@pytest.mark.parametrize("caption", CAPTIONS)
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_complete_serialized_sequences_after_plain_text_captions_are_redacted(caption, encode, decode):
    callback = _callback("first-private-line\nlast-private-line")
    values = ["public-before", "first-private-line", "last-private-line", "public-after"]
    shown = callback._redact_text(caption + encode(values))
    assert shown.startswith(caption)
    assert decode(shown[len(caption):]) == ["public-before", MASK, MASK, "public-after"]


@pytest.mark.parametrize("caption", CAPTIONS)
@pytest.mark.parametrize("split", [str.splitlines, lambda value: value.split("\n")])
def test_serialized_physical_lines_after_quoted_captions_are_redacted(caption, split):
    callback = _callback("first-private-line\nlast-private-line")
    values = ["public-before", "first-private-line", "last-private-line", "public-after"]
    expected = ["public-before", MASK, MASK, "public-after"]
    encoded = caption + json.dumps(values, indent=4) + "\npublic-suffix"
    original = split(encoded)
    assert callback._redact(original) == split(caption + json.dumps(expected, indent=4) + "\npublic-suffix")
    assert original == split(encoded)


@pytest.mark.parametrize("caption", [
    "Unclosed ' caption: ",
    'Unclosed " caption: ',
    "Invalid key '[': ",
    'Invalid key "name {": ',
])
@pytest.mark.parametrize("public", [":", ",", ": public", ", public", " ", "", "[", "name ["])
@pytest.mark.parametrize("mapping", [False, True])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_punctuation_public_items_and_keys_do_not_end_caption_quotes(caption, public, mapping, encode, decode):
    callback = _callback("first-private-line\nlast-private-line")
    values = [public, "first-private-line", "last-private-line", "public-after"]
    expected = [public, MASK, MASK, "public-after"]
    if mapping:
        values, expected = {public: values}, {public: expected}
    suffix = " public-suffix"
    shown = callback._redact_text(caption + encode(values) + suffix)
    assert shown.startswith(caption) and shown.endswith(suffix)
    assert decode(shown[len(caption):-len(suffix)]) == expected


@pytest.mark.parametrize("caption", [
    *["Invalid token " + quote + delimiter + quote + ": "
      for quote in ("'", '"') for delimiter in "[](){}"],
    *["(Caption " + quote + delimiter + quote + ") result: "
      for quote in ("'", '"') for delimiter in ("[", "(", "{", "([{")],
    *["[" + quote + delimiter + quote + ": public] result: "
      for quote in ("'", '"') for delimiter in ("[", "(", "{", "([{")],
    *["Read " + quote + first + quote + ", then " + quote + second + quote + ", output: "
      for quote in ("'", '"') for first, second in (("[", "("), ("(", "{"), ("{", "["))],
    *["Read " + quote + "escaped \\\\[" + quote + ", then " + quote + "escaped \\\\(" + quote + ", output: "
      for quote in ("'", '"')],
    "(User's '[' token): ",
    "[User's '{' token] ",
])
@pytest.mark.parametrize("public", ["]", ")", "}"])
@pytest.mark.parametrize("shape", ["flat", "nested", "mapping", "tuple"])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_closing_public_items_after_delimiter_captions_preserve_structured_strings(caption, public, shape, encode,
                                                                                decode):
    lines = ["first-private-line", "last-private-line"]
    callback = _callback("\n".join(lines))
    opaque = "Opaque " + json.dumps(["inner-before"] + lines + ["inner-after"])
    values = [public] + lines + [opaque, "public-after"]
    expected = [public, MASK, MASK, opaque, "public-after"]
    body = {"flat": values, "nested": [values], "mapping": {public: values}, "tuple": tuple(values)}[shape]
    wanted = {"flat": expected, "nested": [expected], "mapping": {public: expected},
              "tuple": tuple(expected)}[shape]
    original = copy.deepcopy(body)
    suffix = " public-suffix"
    text = caption + encode(body) + suffix
    shown = callback._redact_text(text)
    assert shown.startswith(caption) and shown.endswith(suffix)
    assert decode(shown[len(caption):-len(suffix)]) == decode(encode(wanted))
    assert callback._redact_text(caption + "report(" + encode(body) + ")" + suffix) == \
        caption + "report(" + encode(wanted) + ")" + suffix
    direct = caption + "report(" + ", ".join(encode(value) for value in values) + ")" + suffix
    assert callback._redact_text(direct) == direct
    for split in (str.splitlines, lambda value: value.split("\n")):
        physical = split(text)
        saved = list(physical)
        rendered = "\n".join(callback._redact(physical))
        assert rendered.startswith(caption) and rendered.endswith(suffix)
        assert decode(rendered[len(caption):-len(suffix)]) == decode(encode(wanted))
        assert physical == saved
    for prefix, ending in (("[", "]"), ("(", ",)"), ('{"public": ', "}"), ("report(", ")"),
                           ("{", ": 'public'}")):
        structured = caption + prefix + repr(opaque) + ending + suffix
        assert callback._redact_text(structured) == structured
    assert body == original


@pytest.mark.parametrize("caption", [
    "", "Result: ", "User's result: ", 'Invalid token "[": ', 'Invalid token "(": ', 'Invalid token "{": ',
    "Unclosed ' caption: ", 'Unclosed " caption: ',
])
@pytest.mark.parametrize("opening,closing", [("[", "]"), ("(", ")"), ("{", "}")])
@pytest.mark.parametrize("real_run", [False, True])
@pytest.mark.parametrize("shape", ["mapping", "array", "tuple", "key", "scalar", "call"])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_structured_opaque_strings_with_unclosed_tails_preserve_text_and_physical_context(caption, opening, closing,
                                                                                       real_run, shape, encode, decode):
    lines = ["first-private-line", "last-private-line"]
    callback = _callback("\n".join(lines))
    opaque = repr(["inner-before"] + lines + ["inner-after"]) + " " + opening
    values = [closing] + (lines if real_run else []) + ["public-outside"]
    wanted = [closing] + ([MASK] * len(lines) if real_run else []) + ["public-outside"]
    inner = {"mapping": {"public": opaque}, "array": [opaque], "tuple": (opaque,),
             "key": {opaque: "public"}, "scalar": opaque, "call": opaque}[shape]
    body, expected = [inner, values], [inner, wanted]
    original = copy.deepcopy(body)
    if shape == "call":
        literal = "report(" + encode(opaque) + ", " + encode(values) + ")"
        masked = "report(" + encode(opaque) + ", " + encode(wanted) + ")"
    else:
        literal, masked = encode(body), encode(expected)
    text = caption + literal
    assert callback._redact_text(text) == caption + masked
    for split in (str.splitlines, lambda value: value.split("\n")):
        physical = split(text)
        saved = list(physical)
        assert callback._redact(physical) == split(caption + masked)
        assert physical == saved
    if shape != "call":
        assert decode(callback._redact_text(encode(body))) == decode(encode(expected))
    assert body == original


def test_physical_chunks_scan_serialized_context_once_and_keep_literal_matches():
    lines = ["first-private-line", "last-private-line"]
    scalar = "SINGLE_PRIVATE_8092"
    callback = _callback("\n".join(lines), scalar)
    opaque = repr(["inner-before"] + lines + ["inner-after"]) + " ["
    context = json.dumps([{"public": opaque}, ["]", "public-outside"]], indent=4).splitlines()
    standalone = json.dumps(["public-before"] + lines + ["public-after"])
    masked = json.dumps(["public-before", MASK, MASK, "public-after"])
    digest = hashlib.sha256(scalar.encode("utf-8")).hexdigest()
    tail = lines + ["before " + scalar, "before " + digest, repr(lines)]
    body = context + [17, standalone, None] + tail
    original = copy.deepcopy(body)
    expected = context + [17, masked, None, MASK, MASK, "before " + MASK, "before " + MASK, MASK]
    with patch.object(callback, "_serialized_spans", wraps=callback._serialized_spans) as scan:
        assert callback._redact(body) == expected
    assert scan.call_count == 3
    assert [call.args[0] for call in scan.call_args_list] == ["\n".join(context), standalone, "\n".join(tail)]
    assert all(call.kwargs == {"split_lines": True} for call in scan.call_args_list)
    assert body == original


@pytest.mark.parametrize("caption", [
    "",
    "User's result: ",
    "Invalid key 'name [': ",
    'Unclosed " caption: ',
])
@pytest.mark.parametrize("tail", [":", ",", "[", "(", "{", "label:"])
@pytest.mark.parametrize("spaced", [False, True])
@pytest.mark.parametrize("encode", [json.dumps, lambda value: json.dumps(value, indent=4), repr])
@pytest.mark.parametrize("quote", [repr, json.dumps, lambda value: repr(value.encode("utf-8"))])
def test_root_quoted_arrays_mask_only_visible_complete_sequences(caption, tail, spaced, encode, quote):
    callback = _callback("root\nenabled\ntrue")
    values = ["public-before", "root", "enabled", "true", "public-after"]
    encoded = encode(values)
    opaque = quote("public-prefix " + encoded + (" " if spaced else "") + tail)
    text = caption + opaque + " public-suffix"
    expected = text
    if encoded in opaque:
        # An exact array after prose is indistinguishable from the same text inside root quotation.
        expected = text.replace(encoded, encode(["public-before", MASK, MASK, MASK, "public-after"]), 1)
    assert callback._redact_text(text) == expected
    for prefix, suffix in (("[", "]"), ("(", ",)"), ('{"public": ', "}"), ("report(", ")"),
                           ("{", ": 'public'}")):
        structured = caption + prefix + opaque + suffix + " public-suffix"
        assert callback._redact_text(structured) == structured


@pytest.mark.parametrize("secret", ["root\nenabled\ntrue", "first-private-line\nlast-private-line", "x\n\nx\n"])
@pytest.mark.parametrize("encode", [
    json.dumps,
    lambda value: json.dumps(value, separators=(",", ":")),
    lambda value: json.dumps(value, ensure_ascii=False),
])
@pytest.mark.parametrize("tail", ["users", "label:", "label,", "label;", "label.", "label!", "label?", "label("])
@pytest.mark.parametrize("suffix", [
    "", ";", ".", "!", "?", " output", " users' output", " owners' [public] output",
    " O'Brien's output", "; users' output", " users': output",
])
def test_indistinguishable_root_quote_and_prose_constructions_show_the_same_masked_sequence(secret, encode, tail,
                                                                                          suffix):
    callback = _callback(secret)
    lines = secret.splitlines()
    values = ["public-before"] + lines + ["public-after"]
    payload = encode(values)
    prose = "'Caption started: " + payload + " " + tail + "'" + suffix
    opaque = repr("Caption started: " + payload + " " + tail) + suffix
    assert prose == opaque
    expected = "'Caption started: " + encode(["public-before"] + [MASK] * len(lines) + ["public-after"])
    expected += " " + tail + "'" + suffix
    assert callback._redact_text(prose) == callback._redact_text(opaque) == expected
    physical = prose.splitlines()
    original = list(physical)
    assert callback._redact(physical) == expected.splitlines()
    assert physical == original


@pytest.mark.parametrize("quote", [repr, json.dumps, lambda value: repr(value.encode("utf-8"))])
@pytest.mark.parametrize("tail", ["[", "(", "{", "]", ")", "}", "label:", "label,", "label;", "label."])
@pytest.mark.parametrize("suffix", [";", ".", "!", "?", " users' output", " owners': public"])
@pytest.mark.parametrize("public", [":", ",", "", " ", "[", "(", "{"])
def test_arrays_after_quoted_prose_and_public_suffixes_are_redacted(quote, tail, suffix, public):
    callback = _callback("root\nenabled\ntrue")
    values = [public, "root", "enabled", "true", "public-after"]
    expected = [public, MASK, MASK, MASK, "public-after"]
    prefix = quote("public caption " + tail) + suffix + " result: "
    encoded = json.dumps(values)
    original = prefix + encoded + " public-suffix"
    assert callback._redact_text(original) == prefix + json.dumps(expected) + " public-suffix"


@pytest.mark.parametrize("encode", [repr, json.dumps, lambda value: json.dumps(value, ensure_ascii=False)])
def test_cached_complete_array_literals_are_masked_inside_quoted_values(encode):
    lines = ["first-private-line", "last-private-line"]
    callback = _callback("\n".join(lines))
    encoded = encode(lines)
    assert callback._redact_text(encoded) == MASK
    assert callback._redact_text("before " + encoded + " after") == "before " + MASK + " after"
    shown = callback._redact_text(repr({"nested": encoded}))
    assert "first-private-line" not in shown and "last-private-line" not in shown
    assert ast.literal_eval(shown) == {"nested": MASK}


@pytest.mark.parametrize("barrier", ["gap", 17, False, None, {}, [], {"enabled": "true"}, ("enabled", "true")])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_nonmatching_items_and_nested_containers_break_serialized_sequences(barrier, encode, decode):
    callback = _callback("root\nenabled\ntrue")
    body = ["public-before", "root", barrier, "enabled", "true", "public-after"]
    encoded = encode(body)
    assert callback._redact_text(encoded) == encoded
    assert callback._redact(body) == ["public-before", "root", callback._redact(barrier),
                                      "enabled", "true", "public-after"]


@pytest.mark.parametrize("public", [
    '"root", "enabled", "true"',
    'report("root", "enabled", "true")',
    'service.report("root", "enabled", "true")',
    '{"root": "enabled", "status": "true"}',
    "{('root', 'enabled', 'true'): 'public'}",
    '["root" "enabled", "true"]',
    '["root", "enabled", "true"',
    r'["root", "\q", "enabled", "true"]',
])
def test_quoted_words_mapping_keys_and_incomplete_arrays_remain_public(public):
    assert _callback("root\nenabled\ntrue")._redact_text(public) == public


@pytest.mark.parametrize("caption", ["", "Result: ", "User's result: "])
@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("operator", ["+", " + "])
@pytest.mark.parametrize("opening,closing", [("[", "]"), ("(", ")")])
@pytest.mark.parametrize("encode,decode", ENCODERS)
def test_quoted_expression_items_break_complete_serialized_sequences(caption, position, operator, opening, closing,
                                                                    encode, decode):
    callback = _callback("root\nenabled\ntrue")
    values = ["public-before", "root", "enabled", "true", "public-after"]
    tokens = [encode(value) for value in values]
    tokens[position + 1] += operator + encode("-public")
    literal = opening + ",\n".join(tokens) + closing
    tree = ast.parse(literal, mode="eval")
    assert isinstance(tree.body.elts[position + 1], ast.BinOp)
    assert decode(encode(values)) == values
    text = caption + literal + " public-suffix"
    assert callback._redact_text(text) == text
    physical = text.splitlines()
    original = list(physical)
    assert callback._redact(physical) == physical
    assert physical == original


@pytest.mark.parametrize("callee", [
    "report",
    "service.report",
    "factory()",
    "(report)",
    "handlers[0]",
    "factory()[0]",
    "(report or fallback)",
    "(lambda *args: args)",
    "report.__call__",
    'handlers["public-key"]',
    '(getattr(report, "send"))',
    'handler_map[("group", "name")]',
    "factory().items()[0]",
    "(report if enabled else fallback)",
    "factory().handler",
    "handlers[0].report",
    "handlers [0]",
    "factory() [0]",
    "handlers [0].report",
    "factory() .handler",
    "handlers\t[0]",
    "[report][0]",
    "[report] [0]",
    '{"send": report}["send"]',
    '{"send": report} ["send"]',
    "([report][0])",
    '({"send": report}["send"])',
    'obj.__dict__["send"]',
    "(report,)[0]",
    "(report, ) [0]",
    '(lambda mode="public": report)',
    "(report + fallback)",
    "(report | fallback)",
])
@pytest.mark.parametrize("separator", ["", " "])
@pytest.mark.parametrize("caption", [
    "", "User's result: ", "Invalid key '(': ", 'Invalid key "name [": ', "Unclosed ' caption: ",
])
@pytest.mark.parametrize("suffix", ["", " public-suffix", " user's output", " public; end!"])
@pytest.mark.parametrize("encode", [json.dumps, repr])
def test_callable_arguments_remain_public_but_nested_array_arguments_are_redacted(callee, separator, caption, suffix,
                                                                                encode):
    callback = _callback("root\nenabled\ntrue")
    values = ["public-before", "root", "enabled", "true", "public-after"]
    direct = callee + separator + "(" + ", ".join(encode(value) for value in values) + ")"
    assert isinstance(ast.parse(direct, mode="eval").body, ast.Call)
    assert callback._redact_text(caption + direct + suffix) == caption + direct + suffix
    nested = callee + separator + "(" + encode(values) + ")"
    assert isinstance(ast.parse(nested, mode="eval").body.args[0], ast.List)
    expected = callee + separator + "(" + encode(["public-before", MASK, MASK, MASK, "public-after"]) + ")"
    assert callback._redact_text(caption + nested + suffix) == caption + expected + suffix


@pytest.mark.parametrize("caption", [
    "[INFO] ", "Result [INFO]: ", "(Public caption) ", "[public labels] ", "[User's result] ",
])
@pytest.mark.parametrize("public", [":", ",", "", " ", "[", "(", "{"])
def test_tuple_arrays_after_noncallable_prose_delimiters_are_redacted(caption, public):
    callback = _callback("root\nenabled\ntrue")
    values = (public, "root", "enabled", "true", "public-after")
    expected = (public, MASK, MASK, MASK, "public-after")
    assert callback._redact_text(caption + repr(values)) == caption + repr(expected)


@pytest.mark.parametrize("public", [":", ",", "", " ", "[", "(", "{"])
@pytest.mark.parametrize("encode", [json.dumps, repr])
def test_indexed_callable_context_separates_arguments_from_array_values(public, encode):
    callback = _callback("root\nenabled\ntrue")
    values = [public, "root", "enabled", "true", "public-after"]
    prefix = "Result [INFO] "
    direct = prefix + repr(tuple(values))
    assert callback._redact_text(direct) == direct
    nested = prefix + "(" + encode(values) + ")"
    expected = prefix + "(" + encode([public, MASK, MASK, MASK, "public-after"]) + ")"
    assert callback._redact_text(nested) == expected


@pytest.mark.parametrize("family", ["json", "bytes"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("which", [0, 1])
def test_colliding_aliases_preserve_all_learned_sequences(family, reverse, which):
    first, second = (("\U0001f600", "\ud83d\ude00") if family == "json" else ("\u00e9", "\udcc3\udca9"))
    secrets = [first + "\nSYNTHETIC_ALPHA_8092", second + "\nSYNTHETIC_BETA_9082"]
    callback = _callback(*(reversed(secrets) if reverse else secrets))
    lines = secrets[which].splitlines()
    if family == "json":
        encoded = json.dumps(["public-before"] + lines + ["public-after"], indent=4)
        shown = json.loads(callback._redact_text(encoded))
        assert shown == ["public-before", MASK, MASK, "public-after"]
    else:
        values = ["public-before", lines[0].encode("utf-8", "surrogateescape"), lines[1], "public-after"]
        shown = ast.literal_eval(callback._redact_text(repr(values)))
        assert shown == ["public-before", MASK.encode(), MASK, "public-after"]


@pytest.mark.parametrize("reverse", [False, True])
def test_bytes_aliases_do_not_merge_distinct_text_values(reverse):
    secrets = ["\u00e9\nTailA_8092", "\udcc3\udca9\nTailB_8092"]
    callback = _callback(*(reversed(secrets) if reverse else secrets))
    for values in (["before", "\udcc3\udca9", "TailA_8092", "after"],
                   ["before", "\u00e9", "TailB_8092", "after"]):
        encoded = json.dumps(values, indent=4)
        assert callback._redact_text(encoded) == encoded


@pytest.mark.parametrize("family", ["json", "bytes"])
def test_ambiguous_aliases_preserve_overlapping_prefix_states(family):
    first, second = (("\U0001f600", "\ud83d\ude00") if family == "json" else ("\u00e9", "\udcc3\udca9"))
    callback = _callback(first + "\n" + second + "\nTail_8092")
    if family == "json":
        values = ["before", first, first, first, "Tail_8092", "after"]
        encoded = json.dumps(values, indent=4)
        assert json.loads(callback._redact_text(encoded)) == ["before", first, MASK, MASK, MASK, "after"]
    else:
        line = first.encode()
        values = [b"before", line, line, line, b"Tail_8092", b"after"]
        assert ast.literal_eval(callback._redact_text(repr(values))) == [
            b"before", line, MASK.encode(), MASK.encode(), MASK.encode(), b"after"]


def test_ambiguous_token_matching_agrees_with_complete_window_matches():
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    callback = _callback("\u00e9\n\udcc3\udca9\nTail_8092")
    pool = (repr("\u00e9".encode()), repr("Tail_8092"), repr("gap"))
    for width in range(7):
        for values in itertools.product(pool, repeat=width):
            expected = set()
            for lines in callback._sequences:
                for start in range(len(values) - len(lines) + 1):
                    if all(token in callback._token_lines[line][0]
                           for token, line in zip(values[start:start + len(lines)], lines)):
                        expected.update(range(start, start + len(lines)))
            assert keeper_redact._token_indices(values, callback._token_sequences, callback._sequences) == expected


def test_overlapping_sequences_and_empty_tokens_are_masked_once():
    callback = _callback("first-8092\nshared-9082", "shared-9082\nlast-1092", "x\n\nx\n")
    values = ["before", "first-8092", "shared-9082", "last-1092", "x", "", "x", "", "x", "after"]
    shown = callback._redact_text(json.dumps(values, indent=4))
    assert json.loads(shown) == ["before"] + [MASK] * 8 + ["after"]
    assert MASK * 2 not in shown


@pytest.mark.parametrize("separator", ["\r\n", "\r", "\u0085", "\u2028", "\u2029", "\v", "\f", "\x1c"])
@pytest.mark.parametrize("split_lines", [False, True])
def test_serialized_token_spans_project_across_every_physical_line(separator, split_lines):
    secret = "SYNTHETIC_FIRST_8092" + separator + "SYNTHETIC_SECOND_8092\nSYNTHETIC_LAST_8092"
    callback = _callback(secret)
    encoded = json.dumps(["public-before"] + secret.split("\n") + ["public-after"], ensure_ascii=False, indent=4)
    physical = encoded.splitlines() if split_lines else encoded.split("\n")
    original = list(physical)
    shown = callback._redact(physical)
    rendered = "\n".join(shown)
    assert shown[0] == "[" and shown[-1] == "]"
    assert "public-before" in rendered and "public-after" in rendered
    assert all(marker not in rendered for marker in (
        "SYNTHETIC_FIRST_8092", "SYNTHETIC_SECOND_8092", "SYNTHETIC_LAST_8092"))
    assert physical == original


def test_nontext_physical_entries_are_barriers_and_originals_are_unchanged():
    callback = _callback("root\nenabled\ntrue")
    physical = json.dumps(["before", "root", "enabled", "true", "after"], indent=4).splitlines()
    physical.insert(3, {"public": 17})
    original = copy.deepcopy(physical)
    result = SimpleNamespace(result={"stdout_lines": physical, "again": physical},
                             task=SimpleNamespace(action="command"))
    callback._scrub(result)
    assert result.result == {"stdout_lines": original, "again": original}
    assert physical == original


def test_projected_and_literal_spans_merge_on_the_original_text():
    callback = _callback("first-8092\nlast-9082", 'prefix ["public", "first')
    shown = callback._redact_text('prefix ["public", "first-8092", "last-9082"] suffix')
    assert shown == '****", "****"] suffix'


def test_output_uses_cached_prefixes_and_bounded_ambiguous_mask_storage():
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    lines = ["line-{:04d}-8092".format(index) for index in range(1024)]
    callback = _callback("\n".join(lines))
    with patch.object(keeper_redact, "_sequence_prefix", side_effect=AssertionError("Do not rebuild prefixes.")), \
            patch.object(keeper_redact, "_token_pattern", side_effect=AssertionError("Do not rebuild aliases.")):
        callback._learn("keeper_get", {"value": "\n".join(lines)})
        encoded = json.dumps(["before"] + lines + ["after"], indent=4)
        assert json.loads(callback._redact_text(encoded)) == ["before"] + [MASK] * len(lines) + ["after"]
    assert all(aliases is not None and positions is None and dense is None and cache is None
               for pair in callback._token_sequences.values() for aliases, positions, dense, cache in pair)

    lines[0], lines[-1] = "\u00e9", "\udcc3\udca9"
    callback = _callback("\n".join(lines))
    values = [b"before"] + [line.encode("utf-8", "surrogateescape") for line in lines] + [b"after"]
    assert ast.literal_eval(callback._redact_text(repr(values))) == [b"before"] + [MASK.encode()] * len(lines) + [b"after"]
    for pair in callback._token_sequences.values():
        for aliases, positions, dense, cache in pair:
            assert aliases is None and positions is not None
            assert sum(len(indices) for indices in positions.values()) <= 6 * len(lines)
            assert all((mask.bit_length() + 7) // 8 <= 4 * len(positions[token])
                       for token, mask in dense.items())
            assert len(cache) <= 16


@pytest.mark.parametrize("cycles", [64, 256])
@pytest.mark.parametrize("token_classes", [1, 18])
def test_dense_masks_are_not_rebuilt_after_sparse_cache_pollution(cycles, token_classes):
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    cycle = ["\U0001f600", "\ud83d\ude00"] + [
        "cycle-value-{:02d}-8092".format(index) for index in range(1, token_classes)]
    tails = ["tail-value-{:02d}-9082".format(index) for index in range(16)]
    lines = cycle * cycles + tails
    callback = _callback("\n".join(lines))
    values = ["public-before"] + tails + lines + ["public-after"]
    with patch.object(keeper_redact, "_position_mask", wraps=keeper_redact._position_mask) as build:
        shown = callback._redact_text(json.dumps(values, indent=4))
    assert json.loads(shown) == ["public-before"] + tails + [MASK] * len(lines) + ["public-after"]
    assert build.call_count <= len(tails)


@pytest.mark.parametrize("ambiguous", [False, True])
def test_short_serialized_runs_skip_long_pattern_lookups_and_hashing(ambiguous):
    hashes = accesses = 0

    class CountedLine(str):
        def __hash__(self):
            nonlocal hashes
            hashes += 1
            return super().__hash__()

    class CountedAlternatives(tuple):
        def __getitem__(self, key):
            nonlocal accesses
            accesses += 1
            return super().__getitem__(key)

    shared = "SYNTHETIC_SHARED_8092"
    lines = [shared] * 512 + (["\U0001f600", "\ud83d\ude00"] if ambiguous else [])
    callback = _callback("\n".join(lines))
    patterns, prefixes = {}, {}
    for pattern, alternatives in callback._token_sequences.items():
        counted = tuple(CountedLine(line) for line in pattern)
        patterns[counted] = CountedAlternatives(alternatives)
        prefixes[counted] = callback._sequences[pattern]
    callback._token_sequences, callback._sequences = patterns, prefixes
    hashes = accesses = 0
    encoded = json.dumps([shared, "PUBLIC_GAP_7013"] * 512)
    assert callback._redact_text(encoded) == encoded
    assert hashes == 0 and accesses == 0


def test_tokenizer_has_bounded_character_work_and_never_evaluates_unknown_literals():
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    accesses = 0

    class CountedText(str):
        def __getitem__(self, key):
            nonlocal accesses
            accesses += 1
            assert accesses <= 8 * len(self)
            return super().__getitem__(key)

    callback = _callback("root\nenabled\ntrue")
    value = CountedText(json.dumps(["root", "enabled", "true"] * 1024, indent=4))
    assert keeper_redact._string_runs(value, callback._token_values)
    randomizer = random.Random(8092)
    alphabet = "[]{}(),:\\\"'b ruotenald\n\t"
    with warnings.catch_warnings(record=True) as emitted:
        for _ in range(500):
            text = "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(1, 128)))
            assert isinstance(callback._redact_text(text), str)
    assert emitted == []


@pytest.mark.parametrize("size", [512, 2048, 8192])
@pytest.mark.parametrize("pattern", [
    "'", '"', "b'", 'b"', "['", '("', "' [ : ' , ", "\\'", '[","', "[] [",
    '{"f": f} ["key"] (', '(lambda mode="public": handler) ', "(report + fallback) ", "(report | fallback) ",
    'Invalid token "[": ["]", ', "Invalid token '(': [')', ", '[Caption "{"] result: ["}", ',
    "Read '[', then '(', output: [']', ", "(User's '[' token): [']', ",
])
def test_quote_boundary_recovery_has_linear_character_work(size, pattern):
    from keeper_secrets_manager_ansible.plugins.callback import keeper_redact

    accesses = 0

    class CountedText(str):
        def __getitem__(self, key):
            nonlocal accesses
            accesses += 1
            assert accesses <= 8 * len(self)
            return super().__getitem__(key)

    callback = _callback("root\nenabled\ntrue")
    text = CountedText(pattern * size)
    assert isinstance(keeper_redact._string_runs(text, callback._token_values), list)


def _task_result(output, name):
    panel = output.split("TASK [" + name + "]", 1)[1].split("TASK [", 1)[0]
    found = re.search(r"(?:ok|changed): \[localhost\] =>\s*", panel)
    assert found is not None, panel
    return json.JSONDecoder().raw_decode(panel[found.end():].lstrip())[0]


def _native_context(tmp_path, secret, public):
    record = mock.Record(title="Synthetic multiline record", record_type="login")
    record.field("password", secret)
    response = mock.Response()
    response.add_record(record=record)
    public_metadata = {"root": "enabled", "status": "true"}
    values = ["public-before"] + secret.split("\n") + ["public-after"]
    pretty = json.dumps(values, ensure_ascii=False, indent=4)
    public_file = tmp_path / "public-output.txt"
    public_file.write_text(public, encoding="utf-8")
    serialized_file = tmp_path / "serialized-output.txt"
    serialized_file.write_text(pretty, encoding="utf-8")
    surrounded = "(['public-before'] + fetched.value.split(line_feed) + ['public-after'])"
    tasks = [
        {"name": "Fetch multiline value", "keeper_get": {"uid": "{{ record_uid }}", "field": "password"},
         "register": "fetched"},
        {"name": "Display raw lines", "debug": {"msg": "{{ " + surrounded + " }}"}, "register": "raw"},
        {"name": "Display JSON lines", "debug": {"msg": "{{ " + surrounded + " | to_json }}"},
         "register": "ordinary"},
        {"name": "Display compact JSON lines", "debug": {
            "msg": "{{ " + surrounded + " | to_json(ensure_ascii=False, separators=[',', ':']) }}"},
         "register": "compact"},
        {"name": "Display nice JSON lines", "debug": {
            "msg": "{{ " + surrounded + " | to_nice_json(ensure_ascii=False) }}"}, "register": "nice"},
    ]
    for name, path, register in (("Return public output", public_file, "public_result"),
                                 ("Return serialized output", serialized_file, "serialized_result")):
        tasks.append({"name": name, "command": {"argv": [
            sys.executable, "-c",
            "import pathlib,sys; text=pathlib.Path(sys.argv[1]).read_text(); "
            "sys.stdout.write(text); sys.stderr.write(text)", str(path)]}, "register": register})
    tasks.extend([
        {"name": "Display public metadata", "debug": {"msg": "{{ public_metadata }}"}},
        {"name": "Display registered public output", "debug": {"msg": {
            "text": "output: {{ public_result.stdout }}", "lines": "{{ public_result.stdout_lines }}"}}},
        {"name": "Display registered serialized output", "debug": {"msg": {
            "text": "output: {{ serialized_result.stdout }}", "error": "output: {{ serialized_result.stderr }}",
            "lines": "{{ serialized_result.stdout_lines }}", "error_lines": "{{ serialized_result.stderr_lines }}"}}},
        {"name": "Verify registered originals", "assert": {"quiet": True, "that": [
            "fetched.value == expected_secret", "raw.msg == expected_values",
            "ordinary.msg | from_json == expected_values", "compact.msg | from_json == expected_values",
            "nice.msg | from_json == expected_values",
            "public_result.stdout == expected_public", "public_result.stderr == expected_public",
            "public_result.stdout_lines == expected_public.splitlines()",
            "public_result.stderr_lines == expected_public.splitlines()",
            "serialized_result.stdout == expected_pretty", "serialized_result.stderr == expected_pretty",
            "serialized_result.stdout_lines == expected_pretty.splitlines()",
            "serialized_result.stderr_lines == expected_pretty.splitlines()",
        ]}, "no_log": True},
    ])
    playbook = tmp_path / "context.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "my_systems", "gather_facts": False,
        "vars": {"expected_secret": secret, "expected_public": public, "expected_values": values,
                 "expected_pretty": pretty, "line_feed": "\n", "public_metadata": public_metadata},
        "tasks": tasks,
    }]), encoding="utf-8")
    framework = AnsibleTestFramework(
        playbook=str(playbook), stdout_callback="keeper_redact", mock_responses=[response],
        vars={"record_uid": record.uid, "keeper_config": mock.MockConfig.make_base64(),
              "ansible_python_interpreter": sys.executable},
    )
    (tmp_path / "inventory").mkdir()
    shutil.copyfile(Path(framework.base_dir) / "inventory/all", tmp_path / "inventory/all")
    framework.base_dir = str(tmp_path)
    for name in list(sys.modules):
        if name.startswith("ansible"):
            sys.modules.pop(name, None)
    status, out, err = framework.run()
    output = out + err
    assert status.get("ok") == len(tasks) and status.get("failed") == 0, output
    assert "Loading callback plugin keeper_redact" in output
    assert "Callback dispatch" not in output and "Failure using" not in output
    return {task["name"]: _task_result(output, task["name"]) for task in tasks}, pretty, values


@pytest.mark.parametrize("secret,public", [
    ("user: bob\n    \npass: synthetic-8092!\n", json.dumps({"a": {"b": 1}}, indent=4)),
    ("root\nenabled\ntrue", "service root is enabled and true"),
    (KNOWN_PEM, FOREIGN_PEM),
    ("first-8092\nx\nlast-9082", "ordinary public output"),
    ('quoted"euro-\u20ac-first\\8092\nlast-\u6f22-9082', "ordinary public output"),
    ("x\n\nx\n", "ordinary public output"),
    *[("SYNTHETIC_FIRST_8092" + separator + "SYNTHETIC_SECOND_8092\nSYNTHETIC_LAST_8092",
       "ordinary public output") for separator in ("\u0085", "\u2028", "\u2029")],
], ids=["indentation", "common-words", "foreign-key", "short-line", "escaped-unicode", "empty-lines",
        "nel", "line-separator", "paragraph-separator"])
def test_native_complete_contexts_preserve_public_output_and_registered_originals(tmp_path, secret, public):
    bodies, pretty, values = _native_context(tmp_path, secret, public)
    expected = ["public-before"] + [MASK] * (len(values) - 2) + ["public-after"]
    assert bodies["Fetch multiline value"]["value"] == MASK
    assert bodies["Display raw lines"]["msg"] == expected
    for name in ("Display JSON lines", "Display compact JSON lines", "Display nice JSON lines"):
        assert json.loads(bodies[name]["msg"]) == expected
    public_result = bodies["Return public output"]
    for name in ("stdout", "stderr"):
        assert public_result[name] == public
    for name in ("stdout_lines", "stderr_lines"):
        assert public_result[name] == public.splitlines()
    assert bodies["Display public metadata"]["msg"] == {"root": "enabled", "status": "true"}
    assert bodies["Display registered public output"]["msg"] == {"text": "output: " + public,
                                                               "lines": public.splitlines()}
    serialized = bodies["Return serialized output"]
    registered = bodies["Display registered serialized output"]["msg"]
    for name in ("stdout", "stderr"):
        assert json.loads(serialized[name]) == expected
    for name in ("text", "error"):
        assert registered[name].startswith("output: ")
        assert json.loads(registered[name][len("output: "):]) == expected
    for physical in (serialized["stdout_lines"], serialized["stderr_lines"], registered["lines"],
                     registered["error_lines"]):
        rendered = "\n".join(physical)
        assert physical[0] == "[" and physical[-1] == "]"
        assert "public-before" in rendered and "public-after" in rendered
        for value in values[1:-1]:
            for fragment in value.splitlines():
                if fragment.strip():
                    assert json.dumps(fragment, ensure_ascii=False)[1:-1] not in rendered
        assert MASK in rendered
    assert pretty != serialized["stdout"]
