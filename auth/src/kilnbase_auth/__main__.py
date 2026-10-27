import asyncio
import logging.config
import os
import sys

import uvicorn

from . import migrate
from .app import create_app
from .config import ConfigError, load
from .log import CONFIG, log


def main() -> None:
    logging.config.dictConfig(CONFIG)
    try:
        config = load(os.environ)
    except ConfigError as e:
        log.error("%s", e)
        sys.exit(1)

    try:
        migrations = migrate.load(config.migrations_dir)
        applied = asyncio.run(
            migrate.run(config.database_url, migrations, config.authenticator_password)
        )
    except Exception as e:  # noqa: BLE001 - any failure here must stop the service before it serves
        log.error("migration failed: %s", e)
        sys.exit(1)
    for version in applied:
        log.info("applied migration %s", version)

    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port, log_config=CONFIG)  # noqa: S104 - runs inside the container network


if __name__ == "__main__":
    main()
