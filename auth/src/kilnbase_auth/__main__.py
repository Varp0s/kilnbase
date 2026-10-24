import asyncio
import os
import sys

import uvicorn

from . import migrate
from .app import create_app
from .config import ConfigError, load


def main() -> None:
    try:
        config = load(os.environ)
    except ConfigError as e:
        print(f"kilnbase-auth: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        migrations = migrate.load(config.migrations_dir)
        applied = asyncio.run(
            migrate.run(config.database_url, migrations, config.authenticator_password)
        )
    except Exception as e:  # noqa: BLE001 - any failure here must stop the service before it serves
        print(f"kilnbase-auth: migration failed: {e}", file=sys.stderr)
        sys.exit(1)
    for version in applied:
        print(f"kilnbase-auth: applied migration {version}", file=sys.stderr)

    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port, log_level="info")  # noqa: S104 - runs inside the container network


if __name__ == "__main__":
    main()
