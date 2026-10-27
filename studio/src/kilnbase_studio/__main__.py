import logging.config
import os
import sys
from copy import deepcopy

import uvicorn
from kilnbase_auth.log import CONFIG, log

from .app import create_app
from .config import ConfigError, load

LOG_CONFIG = deepcopy(CONFIG)
LOG_CONFIG["formatters"]["json"]["service"] = "studio"


def main() -> None:
    logging.config.dictConfig(LOG_CONFIG)
    try:
        config = load(os.environ)
    except ConfigError as e:
        log.error("%s", e)
        sys.exit(1)
    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port, log_config=LOG_CONFIG)  # noqa: S104 - published on 127.0.0.1 only, see docker-compose.yml


if __name__ == "__main__":
    main()
