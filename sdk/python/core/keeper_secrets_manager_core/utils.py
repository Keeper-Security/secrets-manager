# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
# Contact: sm@keepersecurity.com

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import random
import string
import time
from json import JSONDecodeError
from sys import platform as _platform
from typing import Optional, Tuple
from urllib import parse
import subprocess
import stat
from distutils.util import strtobool

from keeper_secrets_manager_core.keeper_globals import logger_name

ALLOWED_WINDOWS_CONFIG_ADMINS = ['Administrators', 'SYSTEM']
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
        elapsed = tm_base % period  # time elapsed in current period in seconds
        ttl = period - elapsed  # time to live in seconds

        return TotpCode(code, ttl, period)


#  password generation
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


def get_windows_user_sid_and_name(logger=None):
    try:
        user_sid = subprocess.check_output(['whoami', '/user'], encoding='utf-8').splitlines()[-1]
    except subprocess.CalledProcessError as e:
        logger.info(f'Cannot get current Windows user via "whoami": {e}')
        return None, None
    else:
        return reversed(user_sid.split('\\')[-1].split())


def set_config_mode(file, logger=None):

    # Allow the user skip locking down the configuration file's mode.
    if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE", "FALSE"))) is False:
        # For Windows, use icacls. cacls is obsolete.

        if _platform.lower().startswith("win") is True:

            sid, user = get_windows_user_sid_and_name()

            # https://stackoverflow.com/questions/5264595/windows-chmod-600
            # https://github.com/PowerShell/Win32-OpenSSH/issues/132

            # Remove mode inherited by the directory.
            # Remove everyone's access
            # Grant the current user full access
            # Allow Administrators full access
            commands = [
                'icacls.exe "{}" /reset'.format(file),
                'icacls.exe "{}" /inheritance:r'.format(file),
                'icacls.exe "{}" /remove:g Everyone:F'.format(file),
                'icacls.exe "{}" /grant:r Administrators:F'.format(file),
                'icacls.exe "{}" /grant:r *{}:F'.format(file, sid),
            ]
            for command in commands:
                if logger is not None:
                    logger.debug("Set Mode Command " + command)
                output = subprocess.run(command, capture_output=True)
                if output.stderr is not None and "Access is denied" in output.stderr.decode():
                    raise Exception("Access denied to configuration file {}.".format(file))
                if output.stdout is not None and "Failed processing 0 files" not in output.stdout.decode():
                    message = "Could not change the ACL for file '{}'. Set the environmental variable " \
                              "'KSM_CONFIG_SKIP_MODE' to 'TRUE' to skip setting the ACL mode.".format(file)
                    if output.stderr is not None:
                        message += ": " + output.stderr.decode()
                    else:
                        message += "."

                    raise Exception(message)
        else:
            # In Linux/MacOs get file permissions to 0600.
            os.chmod(file, stat.S_IREAD | stat.S_IWRITE)


def check_config_mode(file, color_mod=None, logger=None) -> bool:
    """Check for correct permissions on file

        Return result of check as boolean
    """

    # If we are skipping setting the mode, skip checking.
    if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE", "FALSE"))) is True:
        retval = True
    else:
        # For Windows, use icacls. cacls is obsolete.
        if _platform.lower().startswith("win") is True:

            # If this doesn't error out, then we know the file exists
            output = subprocess.run(["icacls.exe", file], capture_output=True)
            if output.stderr is not None:
                if "Access is denied" in output.stderr.decode():
                    raise PermissionError("Access denied to configuration file {}.".format(file))
                if "cannot find" in output.stderr.decode():
                    raise FileNotFoundError("Cannot find configuration file {}.".format(file))

            # Try to access the file. If it now can't be found, it's a permission problem.
            try:
                with open(file, "r") as fh:
                    fh.close()
            except (FileNotFoundError, PermissionError):
                raise PermissionError("Access denied to configuration file {}.".format(file))

            if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE_WARNING", "FALSE"))) is True:
                retval = True
            else:
                # We need to figure out who we are. subprocess run will use cmd
                sid, user = get_windows_user_sid_and_name()
                if sid is None:
                    # Don't fail check when user SID is missing.
                    retval = True
                else:
                    allowed_users = [u.lower() for u in ALLOWED_WINDOWS_CONFIG_ADMINS + [user]]
                    for line in output.stdout.decode().split("\n"):
                        parts = line[len(file):].split(":")
                        if len(parts) == 2:
                            found_user = parts[0].split("\\").pop()
                            if found_user.lower() not in allowed_users:

                                message = "The config file mode is too open for '{}'. Use `icacls` to remove access " \
                                          "for other users and groups.\n\n".format(file)
                                message += '> icacls.exe "{}" /reset\n'.format(file)
                                message += '> icacls.exe "{}" /inheritance:r\n'.format(file)
                                message += '> icacls.exe "{}" /remove:g Everyone:F\n'.format(file)
                                message += '> icacls.exe "{}" /grant:r Administrators:F\n'.format(file)
                                message += '> icacls.exe "{}" /grant:r *{}:F\n'.format(file, sid)
                                message += "\nTo disable this check, set the environmental variable " \
                                           "'KSM_CONFIG_SKIP_MODE_WARNING' to 'TRUE'."
                                if color_mod is not None:
                                    message = color_mod.Fore.RED + message + color_mod.Style.RESET_ALL

                                print(message, file=sys.stderr)
                                # Prevent multiple nagging per execution.
                                os.environ["KSM_CONFIG_SKIP_MODE_WARNING"] = "TRUE"
                                retval = False
                                break
                    else:
                        retval = True
        else:
            # Can the user read the file? First check if the file exists. If it does, os.access might throw
            # and exception about it not existing. This mean we don't have access.
            if os.path.exists(file) is True:
                try:
                    if os.access(file, os.R_OK) is False:
                        raise PermissionError("Access denied to configuration file {}.".format(file))
                except FileNotFoundError:
                    raise PermissionError("Access denied to configuration file {}.".format(file))

            # Allow user to skip being nagged by warning message.
            if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE_WARNING", "FALSE"))) is True:
                retval = True
            else:
                mode = oct(os.stat(file).st_mode)
                # Make sure group and user have no rights. Allow owner to have anything.
                if mode[-2:] == "00":
                    retval = True
                else:
                    print("The config file mode, {}, is too open. "
                          "It is recommended to execute 'chmod 0600 {}' to remove group and user "
                          "access. To disable this warning, set the environment variable "
                          "'KSM_CONFIG_SKIP_MODE_WARNING' to 'TRUE'.".format(mode[-4:], file), file=sys.stderr)
                    retval = False

    return retval


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH,
                      lowercase: Optional[int] = None,
                      uppercase: Optional[int] = None,
                      digits: Optional[int] = None,
                      special_characters: Optional[int] = None,
                      special_characterset: str = SPECIAL_CHARACTERS):
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
    :param special_characters: minimum number of special characters if positive, exact if 0 or negative
    :param special_characterset: string containing custom set of special characters to pick from
    :return: generated password string
    """

    counts = (lowercase, uppercase, digits, special_characters)
    sum_categories = sum((abs(i) if isinstance(i, int) else 0) for i in counts)

    # If all lengths are exact/negative but don't reach minimum length - convert to minimum/positive lengths
    num_exact_counts = sum(1 for i in counts if isinstance(i, int) and i <= 0)
    if len(counts) == num_exact_counts and sum_categories < length:
        lowercase = abs(lowercase) if isinstance(lowercase, int) and lowercase < 0 else lowercase
        uppercase = abs(uppercase) if isinstance(uppercase, int) and uppercase < 0 else uppercase
        digits = abs(digits) if isinstance(digits, int) and digits < 0 else digits
        special_characters = abs(special_characters) if isinstance(special_characters, int) and special_characters < 0 else special_characters
        logging.getLogger(logger_name).warning("Bad charset lengths - converting exact lengths to minimum lengths")

    extra_count = length - sum_categories if length > sum_categories else 0
    extra_chars = ''
    if lowercase is None or isinstance(lowercase, int) and lowercase > 0:
        extra_chars += string.ascii_lowercase
    if uppercase is None or isinstance(uppercase, int) and uppercase > 0:
        extra_chars += string.ascii_uppercase
    if digits is None or isinstance(digits, int) and digits > 0:
        extra_chars += string.digits
    if special_characters is None or isinstance(special_characters, int) and special_characters > 0:
        extra_chars += special_characterset
    if extra_count > 0 and not extra_chars:
        extra_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + special_characterset

    category_map = [
        (abs(lowercase) if isinstance(lowercase, int) else 0, string.ascii_lowercase),
        (abs(uppercase) if isinstance(uppercase, int) else 0, string.ascii_uppercase),
        (abs(digits) if isinstance(digits, int) else 0, string.digits),
        (abs(special_characters) if isinstance(special_characters, int) else 0, special_characterset),
        (extra_count, extra_chars)
    ]

    password_list = []
    for count, chars in category_map:
        password_list.extend(list(random_sample(count, chars)))
    random.shuffle(password_list)
    return ''.join(password_list)
