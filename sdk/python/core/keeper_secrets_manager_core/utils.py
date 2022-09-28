# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import random
import string
import time
from json import JSONDecodeError
from sys import platform as _platform
from typing import Optional, Tuple
from urllib import parse

from keeper_secrets_manager_core.keeper_globals import logger_name

ENCODING = 'UTF-8'
SPECIAL_CHARACTERS = '''"!@#$%()+;<>=?[]{}^.,'''
DEFAULT_PASSWORD_LENGTH = 32


def get_os():
    if _platform.lower().startswith("linux"):
        return "linux"
    elif _platform.lower().startswith("darwin"):
        return "macOS"
    # elif _platform.lower().startswith("win32"):
    #     return "win32"
    # elif _platform.lower().startswith("win64"):
    #     return "win64"
    else:
        return _platform


def bytes_to_string(b):
    return b.decode(ENCODING)


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


def bytes_to_base64(b):
    return base64.b64encode(b).decode()


def base64_to_bytes(s):
    return base64.urlsafe_b64decode(s)


def base64_to_string(b64s):
    return base64.b64decode(b64s).decode('UTF-8')


def string_to_bytes(s):
    return s.encode(ENCODING)


def url_safe_str_to_bytes(s):
    b = base64.urlsafe_b64decode(s + '==')
    return b


def url_safe_str_to_int(s):
    b = url_safe_str_to_bytes(s)
    return bytes_to_int(b)


def generate_random_bytes(length):
    return os.urandom(length)


def dict_to_json(dictionary):
    return json.dumps(dictionary, indent=4)


def json_to_dict(json_str):

    try:
        resp = json.loads(json_str)
    except JSONDecodeError as jsonDecErr:
        logging.getLogger(logger_name).warning(jsonDecErr)
        resp = None

    return resp


def now_milliseconds():
    return int(time.time() * 1000)


class TotpCode:

    def __init__(self, code, time_left, period):
        self.code = code
        self.time_left = time_left
        self.period = period


def get_totp_code(url):
    # type: (str) -> TotpCode or None
    comp = parse.urlparse(url)
    if comp.scheme != 'otpauth':
        raise ValueError('Not an otpauth URI')

    if comp.scheme == 'otpauth':
        secret = None
        algorithm = 'SHA1'
        digits = 6
        period = 30
        counter = 0

        # parse URL query string
        for k, v in parse.parse_qsl(comp.query):
            if k == 'secret':
                secret = v
            elif k == 'algorithm':
                algorithm = v
            elif k == 'digits':
                digits = int(v) if v.isnumeric() and int(v) > 0 else digits
            elif k == 'period':
                period = int(v) if v.isnumeric() and int(v) > 0 else period
            elif k == 'counter':
                counter = int(v) if v.isnumeric() and int(v) > 0 else counter

        # validate parameters
        if not secret:
            raise ValueError('TOTP secret not found in URI')

        hash = hashlib.sha1
        algorithm = algorithm.upper()
        if algorithm == 'SHA1':
            hash = hashlib.sha1
        elif algorithm == 'SHA256':
            hash = hashlib.sha256
        elif algorithm == 'SHA512':
            hash = hashlib.sha512
        else:
            raise ValueError('Invalid value "{0}" for TOTP algorithm, must be SHA1, SHA256 or SHA512'.format(algorithm))

        if digits not in [6, 7, 8]:
            raise ValueError('TOTP Digits may only be 6, 7, or 8')

        tm_base = counter if counter > 0 else int(datetime.datetime.now().timestamp())
        tm = tm_base / period
        reminder = len(secret) % 8
        if reminder in {2, 4, 5, 7}:
            padding = '=' * (8 - reminder)
            secret += padding
        key = base64.b32decode(secret, casefold=True)
        msg = int(tm).to_bytes(8, byteorder='big')
        hm = hmac.new(key, msg=msg, digestmod=hash)
        digest = hm.digest()

        offset = digest[-1] & 0x0f
        base = bytearray(digest[offset:offset + 4])
        base[0] = base[0] & 0x7f
        code_int = int.from_bytes(base, byteorder='big')
        code = str(code_int % (10 ** digits)).zfill(digits)
        elapsed = tm_base % period; # time elapsed in current period in seconds
        ttl = period - elapsed; # time to live in seconds

        return TotpCode(code, ttl, period)

# password generation
def random_sample(sample_length=0, sample_string=''):
    use_secrets = False
    try:
        # Older version of Python (before 3.6) don't have this module.
        # If not installed, fall back to the original version of the code
        import secrets
        logging.debug("module 'secrets' is installed")
        use_secrets = True
    except ModuleNotFoundError:
        logging.warning("module 'secrets' is not installed")

    sample = ''
    for _ in range(sample_length):
        if use_secrets:
            sample += secrets.choice(sample_string)
        else:
            pos = int.from_bytes(os.urandom(2), 'big') % len(sample_string)
            sample += sample_string[pos]

    return sample

def generate_password(length: int = DEFAULT_PASSWORD_LENGTH,
                      lowercase: Optional[int] = None,
                      uppercase: Optional[int] = None,
                      digits: Optional[int] = None,
                      symbols: Optional[int] = None,
                      special_characters: str = SPECIAL_CHARACTERS):
    """
    generate_password generates a new password of specified minimum length
    with specified number of uppercase, lowercase, digits and special characters.
    Note: If all character groups are unspecified or all have exact zero length
    then password characters are chosen from all groups uniformly at random.
    Note: If all charset lengths are negative or 0 but can't reach the minimum length
    then all exact/negative charset lengths will be treated as minimum number of characters instead.

    :param length: minimum password length - default: 32
    :param lowercase: minimum number of lowercase characters if positive, exact if 0 or negative
    :param uppercase: minimum number of uppercase characters if positive, exact if 0 or negative
    :param digits: minimum number of digits if positive, exact if 0 or negative
    :param symbols: minimum number of special characters if positive, exact if 0 or negative
    :param special_characters: string containing custom set of special characters to pick from
    :return: generated password string
    """

    counts = (lowercase, uppercase, digits, symbols)
    sum_categories = sum((abs(i) if isinstance(i, int) else 0) for i in counts)

    # If all lengths are exact/negative but don't reach minimum length - convert to minimum/positive lengths
    num_exact_counts = sum(1 for i in counts if isinstance(i, int) and i <= 0)
    if len(counts) == num_exact_counts and sum_categories < length:
        lowercase = abs(lowercase) if isinstance(lowercase, int) and lowercase < 0 else lowercase
        uppercase = abs(uppercase) if isinstance(uppercase, int) and uppercase < 0 else uppercase
        digits = abs(digits) if isinstance(digits, int) and digits < 0 else digits
        symbols = abs(symbols) if isinstance(symbols, int) and symbols < 0 else symbols
        logging.getLogger(logger_name).warning("Bad charset lengths - converting exact lengths to minimum lengths")

    extra_count = length - sum_categories if length > sum_categories else 0
    extra_chars = ''
    if lowercase is None or isinstance(lowercase, int) and lowercase > 0:
        extra_chars += string.ascii_lowercase
    if uppercase is None or isinstance(uppercase, int) and uppercase > 0:
        extra_chars += string.ascii_uppercase
    if digits is None or isinstance(digits, int) and digits > 0:
        extra_chars += string.digits
    if symbols is None or isinstance(symbols, int) and symbols > 0:
        extra_chars += special_characters
    if extra_count > 0 and not extra_chars:
        extra_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + special_characters

    category_map = [
        (abs(lowercase) if isinstance(lowercase, int) else 0, string.ascii_lowercase),
        (abs(uppercase) if isinstance(uppercase, int) else 0, string.ascii_uppercase),
        (abs(digits) if isinstance(digits, int) else 0, string.digits),
        (abs(symbols) if isinstance(symbols, int) else 0, special_characters),
        (extra_count, extra_chars)
    ]

    password_list = []
    for count, chars in category_map:
        password_list.extend(list(random_sample(count, chars)))
    random.shuffle(password_list)
    return ''.join(password_list)
