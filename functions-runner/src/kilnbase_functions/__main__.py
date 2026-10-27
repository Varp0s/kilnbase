import logging.config
import os
import subprocess
import sys
import tempfile
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import uvicorn
from kilnbase_auth.log import CONFIG, log

from . import deps, jail
from .app import create_app
from .config import ConfigError, load

LOG_CONFIG = deepcopy(CONFIG)
LOG_CONFIG["formatters"]["json"]["service"] = "functions"


def jail_works(config) -> str | None:
    """Starts one trivial jail, so a host that forbids namespaces fails at boot, not per call."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "main.py").write_text("def handler(request):\n    return 'ok'\n")
        read_fd, write_fd = os.pipe()
        try:
            argv = jail.argv(config, Path(tmp), write_fd)
            res = subprocess.run(  # noqa: S603 - fixed argv
                argv, input=b'{"body_base64": ""}', capture_output=True, pass_fds=(write_fd,),
                timeout=30, check=False,
            )  # fmt: skip
        finally:
            os.close(write_fd)
            os.close(read_fd)
    if res.returncode == 0:
        return None
    return res.stderr.decode(errors="replace")[-500:]


def main() -> None:
    logging.config.dictConfig(LOG_CONFIG)
    try:
        config = load(os.environ)
    except ConfigError as e:
        log.error("%s", e)
        sys.exit(1)
    try:
        config = replace(config, deps_dir=deps.install(config.functions_dir))
    except deps.DepsError as e:
        log.error("%s", e)
        sys.exit(1)
    if problem := jail_works(config):
        log.error(
            "cannot create a sandbox; the container needs the seccomp profile in "
            "functions-runner/seccomp.json and apparmor=unconfined, as in docker-compose.yml, and on "
            "Ubuntu 23.10+ hosts kernel.apparmor_restrict_unprivileged_userns=0: %s",
            problem,
        )
        sys.exit(1)
    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port, log_config=LOG_CONFIG)  # noqa: S104 - reachable only on the functions network


if __name__ == "__main__":
    main()
