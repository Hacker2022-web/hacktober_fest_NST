"""
Backwards-compatible launcher. Prefer the `wippr` command:

    python3 run_demo.py            ->  wippr serve
    python3 run_demo.py --cli ...  ->  wippr ...
"""

import sys

from wippr.cli import main

if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--cli"]:
        args = args[1:] or ["menu"]
    elif not args:
        args = ["serve"]
    sys.exit(main(args))
