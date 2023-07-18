# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# PYTHON_ARGCOMPLETE_OK

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

__requires__ = ['ansible_core']


import errno
import os
import sys
import traceback

from ansible import context
from ansible.errors import AnsibleError, AnsibleOptionsError, AnsibleParserError
from ansible.module_utils._text import to_text


class LastResort(object):
    # OUTPUT OF LAST RESORT
    def display(self, msg, log_only=None):
        print(msg, file=sys.stderr)

    def error(self, msg, wrap_text=None):
        print(msg, file=sys.stderr)


def main(args):
    display = LastResort()

    try:  # bad ANSIBLE_CONFIG or config options can force ugly stacktrace
        import ansible.constants as C
        from ansible.utils.display import Display, initialize_locale
    except AnsibleOptionsError as e:
        display.error(to_text(e), wrap_text=False)
        sys.exit(5)

    initialize_locale()

    cli = None
    me = os.path.basename(sys.argv[0])

    try:
        display = Display()
        print("starting run", me)

        sub = "playbook"
        myclass = "%sCLI" % sub.capitalize()

        try:
            mycli = getattr(__import__("ansible.cli.%s" % sub, fromlist=[myclass]), myclass)
        except ImportError as e:
            # ImportError members have changed in py3
            if 'msg' in dir(e):
                msg = e.msg
            else:
                msg = e.message
            if msg.endswith(' %s' % sub):
                raise AnsibleError("Ansible sub-program not implemented: %s" % me)
            else:
                raise

        b_ansible_dir = os.path.expanduser(os.path.expandvars(b"~/.ansible"))
        try:
            os.mkdir(b_ansible_dir, 0o700)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                display.warning("Failed to create the directory '%s': %s"
                                % (to_text(b_ansible_dir, errors='surrogate_or_replace'),
                                   to_text(exc, errors='surrogate_or_replace')))
        else:
            display.debug("Created the '%s' directory" % to_text(b_ansible_dir, errors='surrogate_or_replace'))

        cli = mycli(args)
        exit_code = cli.run()

    except AnsibleOptionsError as e:
        cli.parser.print_help()
        display.error(to_text(e), wrap_text=False)
        exit_code = 5
    except AnsibleParserError as e:
        display.error(to_text(e), wrap_text=False)
        exit_code = 4

    except AnsibleError as e:
        display.error(to_text(e), wrap_text=False)
        exit_code = 1
    except KeyboardInterrupt:
        display.error("User interrupted execution")
        exit_code = 99
    except Exception as e:
        if C.DEFAULT_DEBUG:
            # Show raw stacktraces in debug mode, It also allow pdb to
            # enter post mortem mode.
            raise
        have_cli_options = bool(context.CLIARGS)
        display.error("Unexpected Exception, this is probably a bug: %s" % to_text(e), wrap_text=False)
        if not have_cli_options or have_cli_options and context.CLIARGS['verbosity'] > 2:
            log_only = False
            if hasattr(e, 'orig_exc'):
                display.vvv('\nexception type: %s' % to_text(type(e.orig_exc)))
                why = to_text(e.orig_exc)
                if to_text(e) != why:
                    display.vvv('\noriginal msg: %s' % why)
        else:
            display.display("to see the full traceback, use -vvv")
            log_only = True
        display.display(u"the full traceback was:\n\n%s" % to_text(traceback.format_exc()), log_only=log_only)
        exit_code = 250

    sys.exit(exit_code)
