"""The standalone executable's entry point (PyInstaller runs this file as __main__)."""

import sys

from tdxguard.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
