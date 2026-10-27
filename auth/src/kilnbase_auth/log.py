"""JSON lines on stderr, the same shape as core: {"ts", "level", "service", "msg", ...fields}."""

import json
import logging

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
CONFIG = {
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
