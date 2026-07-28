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

class KeeperError(Exception):

    def __init__(self, message):

        self.message = message

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
