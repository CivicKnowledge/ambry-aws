

from __future__ import absolute_import

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'docker'

from ambry.cli import prt, fatal, warn, err



def make_parser(cmd):
    config_p = cmd.add_parser('aws', help='Manage AWS resources for Ambry')
    config_p.set_defaults(command='aws')

    asp = config_p.add_subparsers(title='AWS commands', help='AWS commands')

    sp = asp.add_parser('test', help="Juest Testing")
    sp.set_defaults(subcommand=test)


def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        warn('No library: {}'.format(e))
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)

def test(args, l, rc):
    print 'HERE!'