"""Enable ``python -m iocflow`` to run the CLI."""
from iocflow.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
