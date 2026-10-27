import argparse
import sys
from pathlib import Path

from . import backup, doctor, gen_types, init, migrate, rotate_keys


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

    rotate_cmd = commands.add_parser(
        "rotate-keys", help="switch to a new JWT signing key without downtime"
    )
    rotate_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    rotate_mode = rotate_cmd.add_mutually_exclusive_group()
    rotate_mode.add_argument(
        "--retire", action="store_true", help="drop keys that no longer sign from the JWKS"
    )
    rotate_mode.add_argument(
        "--s3", action="store_true", help="replace only the S3 key pair (no overlap period)"
    )

    backup_cmd = commands.add_parser("backup", help="archive the database and stored files")
    backup_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    backup_cmd.add_argument("-o", "--output", type=Path, help="default: kilnbase-backup-<time>.tar")

    restore_cmd = commands.add_parser("restore", help="replace all data with a backup")
    restore_cmd.add_argument("file", type=Path)
    restore_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    restore_cmd.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    migrate_cmd = commands.add_parser("migrate", help="apply the project's SQL migrations")
    migrate_cmd.add_argument("--env-file", type=Path, default=Path(".env"))
    migrate_cmd.add_argument("--dir", type=Path, default=Path("db/migrations"))
    migrate_new = migrate_cmd.add_subparsers(dest="action").add_parser(
        "new", help="create an empty, timestamped migration file"
    )
    migrate_new.add_argument("name")

    args = parser.parse_args()
    if args.command == "init":
        sys.exit(init.run(args.env_file, args.force))
    if args.command == "doctor":
        sys.exit(doctor.run(args.env_file, args.skip_db))
    if args.command == "gen":
        sys.exit(gen_types.run(args.env_file, args.schema, args.output))
    if args.command == "rotate-keys":
        sys.exit(rotate_keys.run(args.env_file, args.retire, args.s3))
    if args.command == "backup":
        sys.exit(backup.backup(args.env_file, args.output))
    if args.command == "migrate" and args.action == "new":
        sys.exit(migrate.new(args.dir, args.name))
    if args.command == "migrate":
        sys.exit(migrate.run(args.env_file, args.dir))
    if args.command == "restore":
        sys.exit(backup.restore(args.env_file, args.file, args.yes))


if __name__ == "__main__":
    main()
