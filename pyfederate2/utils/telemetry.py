import uuid
import logging
import json
import contextvars
from datetime import datetime

from .configs import LOG_LEVEL

tracking_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "tracking_id", default=str(uuid.UUID("00000000-0000-0000-0000-000000000000"))
)
correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=str(uuid.UUID("00000000-0000-0000-0000-000000000000"))
)


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        record.tracking_id = tracking_id.get()
        record.correlation_id = correlation_id.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord):

        json_record = {
            "tracking_id": getattr(record, "tracking_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
            "timestamp": datetime.now().isoformat(),
            "level": getattr(record, "levelname", None),
            "file": getattr(record, "filename", None),
            "line": getattr(record, "lineno", None),
            "message": getattr(record, "msg", None),
        }
        return json.dumps(json_record)


def get_logger(name: str) -> logging.Logger:

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JsonFormatter())
    stream_handler.addFilter(ContextFilter())

    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)
    logger.addHandler(stream_handler)

    return logger
