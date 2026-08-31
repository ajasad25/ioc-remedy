"""Single source of truth for indicator-of-compromise markers.

Every scanner in this package imports from here.

Before this refactor the marker list was copy-pasted into five scripts and had
drifted apart: scan_current.py carried 15 entries, scan_broad.py
15, verify_clean.py 10 -- with different contents. A file
flagged by one tool could therefore be reported clean by another. This module is
the union of all of them, lowercased for case-insensitive comparison.

Generated once from the pre-refactor scripts. Extend MARKERS here rather than
re-copying a list into a new tool.
"""

# Payload markers. Compare against a lowercased copy of the file body.
MARKERS = [
    '0x/cls', '0x/ls',
    'blockscout', 'eth_getblockbynumber',
    'eth_gettransactioncount', '_$_1e42',
    'trongrid', 'aptoslabs',
    'bsc-dataseed', 'bsc-rpc.publicnode',
    'helloipbot', 'a322e5f3d311d3080e6f0121063e9adc2490ef1a',
    'global.r=require', 'global.r =require',
    "global['r']=require", 'global.i="a9-',
    "global['!']='", 'fromcharcode(127)',
]

# Build-config filename fragments (substring match).
CONFIG_HINTS = (
    'tailwind.config.', 'postcss.config.',
    'vite.config.', 'webpack.config.',
    'next.config.', 'rollup.config.',
    'svelte.config.', 'astro.config.',
    'nuxt.config.', 'craco.config.',
    'metro.config.', 'babel.config.',
)

# Fully-qualified build-config filenames (suffix match).
CONFIG_SUFFIXES = (
    'tailwind.config.js', 'tailwind.config.cjs',
    'tailwind.config.mjs', 'tailwind.config.ts',
    'postcss.config.js', 'postcss.config.cjs',
    'postcss.config.mjs', 'postcss.config.ts',
    'vite.config.js', 'vite.config.cjs',
    'vite.config.mjs', 'vite.config.ts',
    'webpack.config.js', 'next.config.js',
    'next.config.mjs', 'rollup.config.js',
)

# Source extensions worth scanning in a broad sweep.
CODE_EXTENSIONS = (
    '.js', '.cjs', '.mjs', '.jsx',
    '.ts', '.tsx', '.mts', '.cts',
)

# Path fragments never worth scanning.
SKIP_PATH_PARTS = (
    'node_modules/', '/dist/', 'dist/',
    '/build/', '.next/', '/vendor/',
    '/coverage/', '.min.js',
)

# Filenames that legitimately contain markers (security tooling, advisories).
BENIGN_BASENAMES = ("scan-malicious-code.sh", "SECURITY.md", "iocs.txt")

# Smallest observed payload adds ~4.7 KB; blobs below this cannot carry it.
MIN_PAYLOAD_SIZE = 4000

# A build config with a line this long is suspicious even with no marker hit.
LONG_LINE_THRESHOLD = 500


def find_markers(body):
    """Return the markers present in *body*, case-insensitively."""
    low = body.lower()
    return [m for m in MARKERS if m in low]


def longest_line(body):
    """Length of the longest line in *body*."""
    return max((len(line) for line in body.splitlines()), default=0)


def is_scannable(path, size=None):
    """True if *path* is worth fetching and scanning in a broad sweep."""
    import os
    if not path.endswith(CODE_EXTENSIONS):
        return False
    if any(part in path for part in SKIP_PATH_PARTS):
        return False
    if os.path.basename(path) in BENIGN_BASENAMES:
        return False
    if size is not None:
        try:
            if int(size) < MIN_PAYLOAD_SIZE:
                return False
        except (TypeError, ValueError):
            return False
    return True


def looks_infected(body):
    """Return (is_suspicious, reasons) for a file body."""
    reasons = []
    hits = find_markers(body)
    if hits:
        reasons.append("markers: " + ", ".join(hits[:4]))
    longest = longest_line(body)
    if longest > LONG_LINE_THRESHOLD:
        reasons.append("long line ({} chars)".format(longest))
    return (bool(reasons), reasons)
