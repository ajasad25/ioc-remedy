"""Subcommand modules.

Each module in this package is discovered automatically by the CLI and must
expose:

    NAME             str   -- the subcommand name
    HELP             str   -- one-line description
    add_arguments(p)       -- attach subcommand-specific flags (optional)
    run(args, config) int  -- do the work, return an exit code

Adding a file here adds a subcommand; there is no central list to update.
"""
