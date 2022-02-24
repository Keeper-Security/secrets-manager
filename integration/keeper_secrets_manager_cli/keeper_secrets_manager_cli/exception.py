import click
from colorama import Fore, Style


class KsmCliException(click.ClickException):

    in_a_shell = False

    def colorize(self):
        if KsmCliException.in_a_shell is False:
            return str(self.message)
        else:
            return Fore.RED + str(self.message) + Style.RESET_ALL

    def format_message(self):
        return self.colorize()

    def __str__(self):
        return self.colorize()


class KsmRecordSyntaxException:
    pass
