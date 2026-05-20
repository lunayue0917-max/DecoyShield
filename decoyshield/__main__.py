"""Module entry point so ``python -m decoyshield`` runs the CLI."""
import sys

from .cli.main import main

if __name__ == "__main__":
    sys.exit(main())
