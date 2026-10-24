import argparse
import sys
from pathlib import Path

from . import init


def main() -> None:
    parser = argparse.ArgumentParser(prog="kilnbase")
    commands = parser.add_subparsers(dest="command", required=True)

    init_cmd = commands.add_parser("init", help="generate keys and a .env file")
    init_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    init_cmd.add_argument("--force", action="store_true", help="overwrite an existing env file")

    args = parser.parse_args()
    if args.command == "init":
        sys.exit(init.run(args.env_file, args.force))


if __name__ == "__main__":
    main()
