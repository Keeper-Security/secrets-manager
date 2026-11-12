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

import requests


class KeeperError(Exception):

    def __init__(self, message, *, result_code=None, status_code=None, additional_info=None):

        self.message = message
        # For an error response of the server: its error code, its HTTP status, and its additional_info
        self.result_code = result_code
        self.status_code = status_code
        self.additional_info = additional_info

        super().__init__(self.message)


class KeeperAccessDenied(Exception):

    def __init__(self, message):

        self.message = message

        super().__init__(self.message)


class KeeperThrottleError(KeeperError):

    """Raised when the Keeper backend throttles requests and the SDK has
    exhausted its automatic retries (see MAX_THROTTLE_RETRIES).

    Subclasses KeeperError so existing ``except KeeperError`` handlers keep
    working; callers that want to react specifically to throttling can catch
    this type instead.
    """

    pass


class KeeperInvalidURLError(KeeperError, requests.exceptions.InvalidURL):
    """A request URL or proxy URL is not valid. The message never contains the URL.

    Subclasses requests.exceptions.InvalidURL so callers that handle the exception that
    requests raises (the Ansible plugin, user code) keep working.
    """

    pass
