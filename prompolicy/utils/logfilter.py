import logging
import os
import socket
from collections import defaultdict
from functools import wraps
from textwrap import wrap as textwrap

from ..tracing import get_traceparent
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)

from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
)

logger_provider = LoggerProvider(
    resource=Resource.create(
        {
            "service.name": "prompolicy",
            "service.instance.id": "prompolicy-otel-log",
        }
    ),
)
set_logger_provider(logger_provider)

exporter = OTLPLogExporter(
    endpoint=os.environ.get(
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://127.0.0.1:4317"
    ),
    insecure=True,
)
logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)

# Set the root logger level to NOTSET to ensure all messages are captured
logging.getLogger().setLevel(logging.NOTSET)

from ..tracing import *

LF_BASE, LF_WEB, LF_POLICY, LF_MODEL, LF_RESPONSES = range(5)

MAX_LOG_LINE = 2000

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
)

levels = defaultdict(bool)

tracer = trace.get_tracer("proxy")

try:
    for n in range(int(os.environ.get("DEBUG", 0))):
        levels[n] = True
except:
    print(f"Cannot set log levels")


class FilteredLogger(object):
    def __init__(self, name, baselevel=logging.INFO, levels=levels, stream=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(baselevel)
        self.levels = levels
        self.logger.addHandler(handler)
        # initialize default level
        self.levels[0] = True

    def wrap(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            self = args[0]
            message = args[1]
            name = func.__name__
            level = kwargs.get("level", 0)
            _ctx = kwargs.get("_ctx", None)
            if message is None:
                return
            if name == "error":
                message += f" trace {get_traceparent(_ctx).header}"
            if self.levels[level] == True:
                for m in textwrap(message, width=MAX_LOG_LINE):
                    getattr(self.logger, name)(m)

        return wrapped

    @wrap
    def info(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.info(message, _ctx)

    @wrap
    def debug(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.debug(message, _ctx)

    @wrap
    def warning(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.warning(message, _ctx)

    @wrap
    def error(self, message: str, level: int = 0, _ctx=None) -> None:
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.error(message, _ctx)
