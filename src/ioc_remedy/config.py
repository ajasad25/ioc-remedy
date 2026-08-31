"""Runtime configuration.

Everything the tools need to know about *where things live* is resolved here.

Before the refactor each script hardcoded absolute paths belonging to one
developer's machine: a home-directory data file, an engine checkout, and (in the
verifier and the restorer) a per-session scratch directory that no longer
existed, which left those two tools broken.

Nothing outside this module may contain an absolute path into a home directory.
tests/test_config.py enforces that.

Resolution order for each setting: explicit argument, environment variable,
then default relative to the working directory.
"""
import os
import pathlib

ENV_PREFIX = "IOC_REMEDY_"


def _env(name, default=None):
    return os.environ.get(ENV_PREFIX + name, default)


class Config:
    """Resolved paths and account settings for one invocation."""

    def __init__(self, workdir=None, engine=None, accounts=None):
        self.workdir = pathlib.Path(
            workdir or _env("HOME_DIR") or os.getcwd()
        ).expanduser().resolve()

        # The ioc-guard scanning engine (optional; only the engine-backed
        # scanner needs it). https://github.com/ajasad25/ioc-guard
        self.engine = pathlib.Path(
            engine or _env("ENGINE") or "~/src/ioc-guard"
        ).expanduser()

        # GitHub logins whose tokens should be tried, most-privileged first.
        # Empty means "use whatever gh is currently authenticated as".
        raw = accounts if accounts is not None else _env("ACCOUNTS", "")
        if isinstance(raw, str):
            raw = [a.strip() for a in raw.split(",") if a.strip()]
        self.accounts = list(raw)

    # --- derived locations -------------------------------------------------

    @property
    def data_dir(self):
        """Where scan results and plans are read from and written to."""
        d = pathlib.Path(_env("DATA_DIR") or (self.workdir / "data"))
        return d.expanduser()

    def data(self, name):
        """Absolute path to a data file, creating the directory on demand."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / name

    @property
    def engine_available(self):
        return (self.engine / "ioc_guard").is_dir()

    def require_engine(self):
        if not self.engine_available:
            raise SystemExit(
                "ioc-guard engine not found at {}\n"
                "Clone it or set {}ENGINE to its location:\n"
                "  git clone https://github.com/ajasad25/ioc-guard ~/src/ioc-guard"
                .format(self.engine, ENV_PREFIX)
            )

    def __repr__(self):
        return "Config(workdir={}, engine={}, accounts={})".format(
            self.workdir, self.engine, self.accounts or "<gh default>")


def add_common_arguments(parser):
    """Attach the flags every subcommand accepts."""
    parser.add_argument("--workdir", metavar="DIR",
                        help="base directory for inputs and outputs "
                             "(default: $%sHOME_DIR or cwd)" % ENV_PREFIX)
    parser.add_argument("--data-dir", metavar="DIR",
                        help="where scan results are written (default: <workdir>/data)")
    parser.add_argument("--engine", metavar="DIR",
                        help="path to the ioc-guard checkout (default: ~/src/ioc-guard)")
    parser.add_argument("--account", action="append", dest="accounts", metavar="LOGIN",
                        help="GitHub login whose gh token to use; repeatable")
    return parser


def from_args(args):
    """Build a Config from parsed argparse arguments."""
    if getattr(args, "data_dir", None):
        os.environ[ENV_PREFIX + "DATA_DIR"] = args.data_dir
    return Config(workdir=getattr(args, "workdir", None),
                  engine=getattr(args, "engine", None),
                  accounts=getattr(args, "accounts", None))
