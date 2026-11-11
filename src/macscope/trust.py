"""Invocation-scoped consent; never a substitute for worker isolation."""
import sys
from .errors import Error

MESSAGE = ('Native processing requires explicit trust in the input. '
           'Hostile-input isolation is not validated. '
           'Use --trust-input (alias --experimental-trusted-input) only for inputs you trust.')


def require(args):
    if getattr(args, 'experimental_trusted_input', False):
        return
    if sys.stdin.isatty():
        sys.stderr.write(MESSAGE + '\nTrust the input for this invocation? [y/N] ')
        sys.stderr.flush()
        answer = sys.stdin.readline()
        if answer.strip().lower() in ('y', 'yes'):
            args.experimental_trusted_input = True
            return
    raise Error('isolation_required', MESSAGE, 3)
