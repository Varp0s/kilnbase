"""JSON lines on stderr, the same shape as core: {"ts", "level", "service", "msg", ...fields}.
With KILNBASE_LOG_DIR set, the same lines also go to <service>.log there (for Studio)."""

import json
import logging
import os
from copy import deepcopy

log = logging.getLogger("kilnbase")


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str = "auth"):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": round(record.created, 3),
            "level": record.levelname.lower(),
            "service": self.service,
            "msg": record.getMessage(),
        }
        if record.name == "uvicorn.access" and isinstance(record.args, tuple):
            _, method, path, _, status = record.args
            # The query string is left out: magic links and OAuth callbacks carry tokens and codes.
            out |= {"msg": "request", "method": method, "path": str(path).split("?", 1)[0]}
            out["status"] = status
        if record.exc_info:
            out["error"] = self.formatException(record.exc_info)
        return json.dumps(out)


_handler = {"handlers": ["stderr"], "level": "INFO", "propagate": False}
_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": JsonFormatter}},
    "handlers": {
        "stderr": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stderr",
        }
    },
    "loggers": {"kilnbase": _handler, "uvicorn": _handler, "uvicorn.access": _handler},
}


def config(service: str) -> dict:
    """dictConfig for one service; one process per container, so rotating the file is safe."""
    out = deepcopy(_CONFIG)
    out["formatters"]["json"]["service"] = service
    if log_dir := os.environ.get("KILNBASE_LOG_DIR", "").strip():
        out["handlers"]["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filename": os.path.join(log_dir, f"{service}.log"),
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 1,
            "delay": True,
        }
        for logger in out["loggers"].values():
            logger["handlers"] = ["stderr", "file"]
    return out


CONFIG = config("auth")
