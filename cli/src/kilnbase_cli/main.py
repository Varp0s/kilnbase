import argparse
import sys
from pathlib import Path

from . import doctor, gen_types, init


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

    gen_cmd = commands.add_parser("gen", help="generate code from the database")
    gen_targets = gen_cmd.add_subparsers(dest="target", required=True)
    types_cmd = gen_targets.add_parser("types", help="TypeScript types for the SDK")
    types_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    types_cmd.add_argument("--schema", default="public")
    types_cmd.add_argument("-o", "--output", type=Path, help="write here instead of stdout")

    args = parser.parse_args()
    if args.command == "init":
        sys.exit(init.run(args.env_file, args.force))
    if args.command == "doctor":
        sys.exit(doctor.run(args.env_file, args.skip_db))
    if args.command == "gen":
        sys.exit(gen_types.run(args.env_file, args.schema, args.output))


if __name__ == "__main__":
    main()
