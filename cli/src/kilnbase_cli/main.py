import argparse
import sys
from pathlib import Path

from . import doctor, init


def main() -> None:
    parser = argparse.ArgumentParser(prog="kilnbase")
    commands = parser.add_subparsers(dest="command", required=True)

    init_cmd = commands.add_parser("init", help="generate keys and a .env file")
    init_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    init_cmd.add_argument("--force", action="store_true", help="overwrite an existing env file")

    doctor_cmd = commands.add_parser(
        "doctor", help="audit secrets and database for common mistakes"
    )
    doctor_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    doctor_cmd.add_argument("--skip-db", action="store_true", help="only check the env file")

    args = parser.parse_args()
    if args.command == "init":
        sys.exit(init.run(args.env_file, args.force))
    if args.command == "doctor":
        sys.exit(doctor.run(args.env_file, args.skip_db))


if __name__ == "__main__":
    main()
