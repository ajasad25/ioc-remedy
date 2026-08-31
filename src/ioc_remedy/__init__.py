"""ioc_remedy -- tooling to find, verify and remediate a supply-chain payload
injected into build-config and source files across many GitHub repositories.

The package grew out of a real incident response. The scripts that did that work
were single-purpose and hardcoded to one machine; this package is the same logic
made re-runnable by anyone against their own repositories.
"""

__version__ = "0.1.0"

from .config import Config                                    # noqa: F401
