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
import binascii
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
from typing import Optional
from urllib import parse
import subprocess
import stat

from keeper_secrets_manager_core.keeper_globals import logger_name
from keeper_secrets_manager_core import exceptions

ALLOWED_WINDOWS_CONFIG_ADMINS = [b'Administrators', b'SYSTEM']
ENCODING = 'UTF-8'
SPECIAL_CHARACTERS = '''"!@#$%()+;<>=?[]{}^.,'''
DEFAULT_PASSWORD_LENGTH = 32


def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError("invalid truth value {!r}".format(val))


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
    """Decode a URL-safe base64 string to bytes.

    Args:
        s: Base64-encoded string to decode

    Returns:
        Decoded bytes

    Raises:
        KeeperError: If the base64 string is None, malformed, or has incorrect padding
    """
    if s is None:
        raise exceptions.KeeperError(
            "base64_to_bytes received None. A required configuration value is "
            "missing, or a server response field was empty. Verify your "
            "configuration is complete, or reinitialize with a fresh "
            "One-Time Token if the local config was lost."
        )
    try:
        return base64.urlsafe_b64decode(s)
    except binascii.Error as e:
        raise exceptions.KeeperError(
            f"Failed to decode base64 data: {str(e)}. "
            "This may indicate a malformed or corrupted value in your configuration. "
            "Please verify your configuration file is valid and has not been truncated."
        )


def base64_to_string(b64s):
    if b64s is None:
        raise exceptions.KeeperError(
            "base64_to_string received None. A required configuration value is "
            "missing, or a server response field was empty. Verify your "
            "configuration is complete, or reinitialize with a fresh "
            "One-Time Token if the local config was lost."
        )
    try:
        return base64.b64decode(b64s).decode('UTF-8')
    except binascii.Error as e:
        raise exceptions.KeeperError(
            f"Failed to decode base64 data: {str(e)}. "
            "This may indicate a malformed or corrupted value in your configuration. "
            "Please verify your configuration file is valid and has not been truncated."
        )


def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == str.encode(s)
    except (Exception,):
        return False


def string_to_bytes(s):
    return s.encode(ENCODING)


def url_safe_str_to_bytes(s):
    if s is None:
        raise exceptions.KeeperError(
            "url_safe_str_to_bytes received None. A required configuration value is "
            "missing, or a server response field was empty. Verify your "
            "configuration is complete, or reinitialize with a fresh "
            "One-Time Token if the local config was lost."
        )
    b = base64.urlsafe_b64decode(s + '==')
    return b


def url_safe_str_to_int(s):
    b = url_safe_str_to_bytes(s)
    return bytes_to_int(b)


def generate_random_bytes(length):
    return os.urandom(length)


def generate_uid_bytes():
    dash = bytes(b'\xf8\x7f')  # 11111000, 0b01111111
    uid_bytes = bytes()
    for _ in range(8):
        uid_bytes = generate_random_bytes(16)
        if dash[0] & uid_bytes[0] != dash[0]:
            break
    if dash[0] & uid_bytes[0] == dash[0]:
        uid_bytes = bytes([uid_bytes[0] & dash[1]]) + uid_bytes[1:]
    return uid_bytes


def dict_to_json(dictionary):
    return json.dumps(dictionary, indent=4)


def json_to_dict(json_str):

    try:
        resp = json.loads(json_str)
    except JSONDecodeError as jsonDecErr:
        logging.getLogger(logger_name).warning(jsonDecErr)
        resp = None

    return resp


def pad_aes_gcm(data: bytes) -> bytes:
    """Pad JSON bytes with trailing spaces before AES-GCM encryption.

    AES-GCM does not hide the plaintext length, so the data is padded to at least 384 bytes
    and then to a multiple of 16 bytes, the same rule that Commander uses. The server rejects
    NSF (Keeper Drive) record data under 412 encrypted bytes (384 bytes plus the 12-byte nonce and
    the 16-byte tag). JSON parsers ignore trailing whitespace.
    """
    padded_len = max(384, len(data))
    if padded_len % 16:
        padded_len += 16 - padded_len % 16
    return data + b' ' * (padded_len - len(data))


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
        # WSL2 systems may run linux whoami command instead and fail
        # whoami: extra operand '/user'
        # Use the full name of the executable - whoami.exe
        user_sid = subprocess.check_output(['whoami.exe', '/user']).splitlines()[-1]
    except subprocess.CalledProcessError as e:
        logger.debug(f'Cannot get current Windows user via "whoami.exe": {e}')
        return None, None
    else:
        return reversed(user_sid.split(b'\\')[-1].rsplit(b' ', 1))


def set_config_mode(file, logger=None):

    try:
        # Allow the user skip locking down the configuration file's mode.
        if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE", "FALSE"))) is False:
            # For Windows, use icacls. cacls is obsolete.

            if _platform.lower().startswith("win") is True:

                sid, user = get_windows_user_sid_and_name()
                if isinstance(sid, bytes):
                    sid = sid.decode()

                # https://stackoverflow.com/questions/5264595/windows-chmod-600
                # https://github.com/PowerShell/Win32-OpenSSH/issues/132

                # Remove mode inherited by the directory.
                # Remove everyone's access
                # Grant the current user full access
                # Allow Administrators full access
                commands = [
                    'icacls.exe "{}" /reset'.format(file),
                    'icacls.exe "{}" /inheritance:r'.format(file),
                    'icacls.exe "{}" /remove Everyone'.format(file),
                    'icacls.exe "{}" /grant:r Administrators:F'.format(file),
                    'icacls.exe "{}" /grant:r *{}:F'.format(file, sid),
                ]
                for command in commands:
                    if logger is not None:
                        logger.debug("Set Mode Command " + command)
                    output = subprocess.run(command, capture_output=True)
                    if output.returncode == 2:
                        raise FileNotFoundError("Cannot find configuration file {}.".format(file))
                    if output.returncode == 5:
                        raise PermissionError("Access denied to configuration file {}.".format(file))
                    if output.returncode == 1332:
                        if logger is not None:
                            logger.debug(f"Failed to set some ACL permissions: {command}")
                        continue
                        # Probably localized group/user names or non-existent/renamed group/user
                        # Error 1332: No mapping between account names and security IDs was done.
                        # Successfully processed 0 files; Failed processing 0 files
                    if output.returncode != 0:
                        message = "Could not change the ACL for file '{}'. Set the environmental variable " \
                                "'KSM_CONFIG_SKIP_MODE' to 'TRUE' to skip setting the ACL mode.".format(file)
                        if output.stderr:
                            message += ": " + str(output.stderr).lstrip("b").strip("'")
                        else:
                            message += "."

                        raise PermissionError(message)
            else:
                # In Linux/MacOs get file permissions to 0600.
                os.chmod(file, stat.S_IREAD | stat.S_IWRITE)
    except (FileNotFoundError, PermissionError):
        raise
    except Exception as e:
        if logger is not None:
            logger.debug("set_config_mode failed: " + str(e))


def _is_windows():
    return _platform.lower().startswith("win")


def _is_config_skip_mode():
    """Return True when KSM_CONFIG_SKIP_MODE is set to a true value.

    A value that is not a truth value does not skip, so the SDK keeps the protection.
    """
    try:
        return bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE", "FALSE")))
    except ValueError:
        return False


# Win32 values for the Windows owner-only file helpers below
_TOKEN_QUERY = 0x0008
_TOKEN_INFORMATION_CLASS_TOKEN_USER = 1
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_CREATE_NEW = 1
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_ERROR_FILE_EXISTS = 80

_win32_security_api = None


def _get_win32_security_api():
    """Load the Win32 functions that the Windows owner-only file helpers use.

    Each function gets its full signature. Without it, 64-bit Python passes and
    returns handles and pointers as 32-bit int values. The WinDLL objects are
    private, so the signatures do not change ctypes.windll for other code.
    """
    global _win32_security_api
    if _win32_security_api is None:
        import ctypes
        import types
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD),
                        ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wintypes.BOOL)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SecurityAttributes),
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel32.CreateFileW.restype = wintypes.HANDLE

        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorOwner.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL)]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi32.EqualSid.restype = wintypes.BOOL

        _win32_security_api = types.SimpleNamespace(
            ctypes=ctypes, wintypes=wintypes, kernel32=kernel32, advapi32=advapi32,
            SecurityAttributes=SecurityAttributes, invalid_handle_value=ctypes.c_void_p(-1).value)
    return _win32_security_api


def _windows_path(file):
    # The Win32 calls need an absolute str path. os.fsdecode also accepts bytes and PathLike values.
    return os.fsdecode(os.path.abspath(file))


def _get_windows_user_sid_string():
    """Return the SID of the user that runs this process, for example S-1-5-21-....

    It reads the process token, so it starts no helper program. Windows only.
    """
    api = _get_win32_security_api()
    ctypes, wintypes, kernel32, advapi32 = api.ctypes, api.wintypes, api.kernel32, api.advapi32

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD(0)
        # The first call only gets the size of the TOKEN_USER data, so it fails by design.
        advapi32.GetTokenInformation(token, _TOKEN_INFORMATION_CLASS_TOKEN_USER, None, 0, ctypes.byref(size))
        if size.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        token_user = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
                token, _TOKEN_INFORMATION_CLASS_TOKEN_USER, token_user, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, and that starts with the pointer to the SID.
        sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_string = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(sid_string.value)
        finally:
            kernel32.LocalFree(sid_string)
    finally:
        kernel32.CloseHandle(token)


def _new_windows_owner_only_descriptor(api):
    """Return a new security descriptor. The caller must free it with LocalFree.

    The owner is the current user. The protected DACL gives full control to the
    current user and to Administrators only, and it takes no entries from the
    folder. set_config_mode() gives the config file the same DACL entries with icacls.
    """
    ctypes = api.ctypes
    sddl = "O:{0}D:P(A;;FA;;;{0})(A;;FA;;;BA)".format(_get_windows_user_sid_string())
    descriptor = ctypes.c_void_p()
    if not api.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def _create_windows_owner_only_file(file):
    """Create an empty file that has the owner-only security descriptor from the start.

    Windows applies the descriptor when it creates the file, so the file never has
    the ACL of its folder. Returns True when the file was created and False when
    it already exists. Windows only. Raises OSError for other errors.
    """
    api = _get_win32_security_api()
    ctypes = api.ctypes
    descriptor = _new_windows_owner_only_descriptor(api)
    try:
        attributes = api.SecurityAttributes(ctypes.sizeof(api.SecurityAttributes), descriptor.value, False)
        handle = api.kernel32.CreateFileW(
            _windows_path(file), _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE, ctypes.byref(attributes),
            _CREATE_NEW, _FILE_ATTRIBUTE_NORMAL, None)
        if handle is None or handle == api.invalid_handle_value:
            error = ctypes.get_last_error()
            if error == _ERROR_FILE_EXISTS:
                return False
            raise ctypes.WinError(error)
        api.kernel32.CloseHandle(handle)
        return True
    finally:
        api.kernel32.LocalFree(descriptor)


def _windows_file_is_owned_by(api, file, sid):
    """Return True when the owner of the file is the given SID.

    Returns False when Windows cannot read the owner, for example when the
    current user has no READ_CONTROL access to a file that another account owns.
    """
    ctypes = api.ctypes
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = api.advapi32.GetNamedSecurityInfoW(
        _windows_path(file), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION, ctypes.byref(owner), None, None, None,
        ctypes.byref(descriptor))
    if result != 0:
        return False
    try:
        return bool(owner.value) and bool(api.advapi32.EqualSid(owner, sid))
    finally:
        api.kernel32.LocalFree(descriptor)


def _set_windows_owner_only_acl(file):
    """Make sure that the current user owns a file, and replace its DACL with the
    protected owner-only DACL of _new_windows_owner_only_descriptor().

    It uses one SetNamedSecurityInfoW call: it starts no helper program, and the
    file does not get a wider ACL between steps. When another account owns the
    file, the same call makes the current user the owner, so the old owner cannot
    change the DACL again. When the current user already owns the file, the call
    sets only the DACL: the owner can always set the DACL, but a change of the
    owner needs WRITE_OWNER access, which a file with Modify access does not give.
    Windows only. Raises OSError when Windows does not accept the change.
    """
    api = _get_win32_security_api()
    ctypes, wintypes = api.ctypes, api.wintypes
    descriptor = _new_windows_owner_only_descriptor(api)
    try:
        owner = ctypes.c_void_p()
        owner_defaulted = wintypes.BOOL()
        if not api.advapi32.GetSecurityDescriptorOwner(
                descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not api.advapi32.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(dacl_present), ctypes.byref(dacl), ctypes.byref(dacl_defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        # A NULL DACL gives everyone full access, so never send one.
        if not owner.value or not dacl_present.value or not dacl.value:
            raise OSError("The owner-only security descriptor has no owner or no DACL.")
        information = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
        new_owner = None
        if not _windows_file_is_owned_by(api, file, owner):
            information |= _OWNER_SECURITY_INFORMATION
            new_owner = owner
        result = api.advapi32.SetNamedSecurityInfoW(
            _windows_path(file), _SE_FILE_OBJECT, information, new_owner, None, dacl, None)
        if result != 0:
            raise ctypes.WinError(result)
    finally:
        api.kernel32.LocalFree(descriptor)


localized_admins = []
def populate_windows_localized_admin_names_win32api():
    """ Uses Win32 API to get localized account names for known admin accounts """

    import ctypes

    ERROR_INVALID_PARAMETER = 87
    ERROR_INSUFFICIENT_BUFFER = 122
    WinLocalSystemSid = 22  # NT AUTHORITY\SYSTEM
    # WinLocalServiceSid = 23  # NT AUTHORITY\LOCAL SERVICE
    WinBuiltinAdministratorsSid = 26  # BUILTIN\Administrators

    advapi32 = ctypes.windll.advapi32

    def get_account_name(sid_type):
        sid_size = ctypes.c_ulong(256)
        sid = (ctypes.c_byte * sid_size.value)()

        if not advapi32.CreateWellKnownSid(sid_type, None, sid, ctypes.byref(sid_size)):
            error = ctypes.GetLastError()
            if error == ERROR_INVALID_PARAMETER or error == ERROR_INSUFFICIENT_BUFFER:
                sid = (ctypes.c_byte * sid_size.value)()
                if not advapi32.CreateWellKnownSid(sid_type, None, sid, ctypes.byref(sid_size)):
                    raise ctypes.WinError()

        name_size = ctypes.c_ulong(0)
        domain_size = ctypes.c_ulong(0)
        sid_name_use = ctypes.c_ulong(0)
        advapi32.LookupAccountSidW(None, sid, None, ctypes.byref(name_size), None, ctypes.byref(domain_size), ctypes.byref(sid_name_use))
        error = ctypes.GetLastError()
        if error and error != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)

        name = (ctypes.c_wchar * name_size.value)()
        domain = (ctypes.c_wchar * domain_size.value)()
        if not advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_name_use)):
            raise ctypes.WinError()

        return domain.value, name.value

    # populate only once - lazy init
    if not localized_admins:
        admins = []
        _, name = get_account_name(WinLocalSystemSid)
        if name:
            admins.append(name)  # SYSTEM: S-1-5-18
        _, name = get_account_name(WinBuiltinAdministratorsSid)
        if name:
            admins.append(name)  # Administrators: S-1-5-32-544

        # WMI names are unicode - convert to console's code page
        if admins:
            cmd = "echo."
            for admin in admins:
                cmd += f" & echo {admin}"
            locout = subprocess.run(["cmd", "/c", cmd], capture_output=True)
            if locout.returncode == 0 and locout.stdout:
                for line in locout.stdout.split(b"\n"):
                    if line.strip():
                        localized_admins.append(line.strip())


def check_config_mode(file, color_mod=None, logger=None) -> bool:
    """Check for correct permissions on file

        Return result of check as boolean
    """

    retval = False
    try:
        # If we are skipping setting the mode, skip checking.
        if bool(strtobool(os.environ.get("KSM_CONFIG_SKIP_MODE", "FALSE"))) is True:
            retval = True
        else:
            # For Windows, use icacls. cacls is obsolete.
            if _platform.lower().startswith("win") is True:

                # If this doesn't error out, then we know the file exists
                output = subprocess.run(["icacls.exe", file], capture_output=True)

                # check the returncode only - error messages could be in any language
                if output.returncode > 0:
                    if output.returncode == 2:
                        raise FileNotFoundError("Cannot find configuration file {}.".format(file))
                    if output.returncode == 5:
                        raise PermissionError("Access denied to configuration file {}.".format(file))
                    raise PermissionError("Error accessing configuration file {}.".format(file))

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
                        populate_windows_localized_admin_names_win32api()
                        allowed_users = set([u.lower() for u in ALLOWED_WINDOWS_CONFIG_ADMINS + localized_admins + [user]])
                        stdout = output.stdout or b""
                        for line in stdout.split(b"\n"):
                            parts = line[len(file):].split(b":")
                            if len(parts) == 2:
                                found_user = parts[0].split(b"\\").pop()
                                if found_user.lower() not in allowed_users:

                                    message = "The config file mode is too open for '{}'. Use `icacls` to remove access " \
                                            "for other users and groups.\n\n".format(file)
                                    message += '> icacls.exe "{}" /reset\n'.format(file)
                                    message += '> icacls.exe "{}" /inheritance:r\n'.format(file)
                                    message += '> icacls.exe "{}" /remove Everyone\n'.format(file)
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
    except (FileNotFoundError, PermissionError):
        raise
    except Exception as e:
        if logger is not None:
            logger.debug("check_config_mode failed: " + str(e))

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
