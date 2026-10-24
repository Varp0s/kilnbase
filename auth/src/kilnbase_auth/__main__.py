import os
import sys

import uvicorn

from .app import create_app
from .config import ConfigError, load


def main() -> None:
    try:
        config = load(os.environ)
    except ConfigError as e:
        print(f"kilnbase-auth: {e}", file=sys.stderr)
        sys.exit(1)
    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port, log_level="info")  # noqa: S104 - runs inside the container network


if __name__ == "__main__":
    main()
