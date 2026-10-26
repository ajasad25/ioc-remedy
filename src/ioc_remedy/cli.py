"""Command-line entry point.

Subcommands are discovered from ioc_remedy.commands rather than listed here, so
adding a module to that package is all it takes to add a command.
"""
import utils.session
import argparse
import importlib
import pkgutil
import sys

from . import __version__, commands as commands_pkg
from .config import add_common_arguments, from_args


def discover():
    """Import every command module, in name order."""
    found = []
    for info in sorted(pkgutil.iter_modules(commands_pkg.__path__),
                       key=lambda i: i.name):
        module = importlib.import_module(
            "{}.{}".format(commands_pkg.__name__, info.name))
        if hasattr(module, "NAME") and hasattr(module, "run"):
            found.append(module)
    return found


def build_parser(modules):
    parser = argparse.ArgumentParser(
        prog="ioc-remedy",
        description="Find, verify and remediate an injected supply-chain "
                    "payload across GitHub repositories.",
        epilog="Run 'ioc-remedy <command> --help' for command-specific options.")
    parser.add_argument("--version", action="version",
                        version="ioc-remedy {}".format(__version__))

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for module in modules:
        sub = subparsers.add_parser(
            module.NAME,
            help=getattr(module, "HELP", ""),
            description=getattr(module, "__doc__", None),
            formatter_class=argparse.RawDescriptionHelpFormatter)
        add_common_arguments(sub)
        if hasattr(module, "add_arguments"):
            module.add_arguments(sub)
        sub.set_defaults(_module=module)
    return parser


def main(argv=None):
    modules = discover()
    parser = build_parser(modules)
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 2

    config = from_args(args)
    try:
        return args._module.run(args, config) or 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
