
class KeeperError(Exception):

    def __init__(self, message):

        self.message = message

        super().__init__(self.message)


class KeeperAccessDenied(Exception):

    def __init__(self, message):

        self.message = message

        super().__init__(self.message)
