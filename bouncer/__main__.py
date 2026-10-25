"""Command line: python3 -m bouncer <command>

  run            start the DNS server and dashboard (the systemd service)
  update         check GitHub for a new signed release and install it
  update-lists   download the block lists now
  netsetup       wait for a network; open the Wi-Fi setup hotspot if needed
  health         exit 0 if the running Bouncer answers
  version        print the version
"""

import asyncio
import logging
import sys

from . import __version__


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "run"
    if cmd == "run":
        logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
        from .app import serve
        asyncio.run(serve())
        return 0
    if cmd == "update":
        from .updater import run_cli
        return run_cli(force="--force" in argv)
    if cmd == "update-lists":
        from .blocklists import run_update_cli
        return run_update_cli()
    if cmd == "netsetup":
        from .netsetup import main as netsetup_main
        return netsetup_main()
    if cmd == "health":
        from .updater import health_check
        return 0 if health_check(timeout=10) else 1
    if cmd == "version":
        print(__version__)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
