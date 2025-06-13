__all__ = [
    "get_tracecontext",
    "instrument",
    "StatusCode",
    "trace",
    "params_to_trace",
    "TraceContextTextMapPropagator",
    "Context",
]
import logging
import os
from typing import Dict

import opentelemetry.sdk.trace.id_generator as idg
from aiohttp import web
from multidict import MultiDict
from opentelemetry import context, trace
from opentelemetry.context.context import Context
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as grpcOTLPSpanExporter,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as httpOTLPSpanExporter,
)
from opentelemetry.instrumentation.aiohttp_server import AioHttpServerInstrumentor
from opentelemetry.sdk.resources import (
    SERVICE_NAME,
    SERVICE_NAMESPACE,
    SERVICE_VERSION,
    Resource,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.trace import NonRecordingSpan, Span, SpanContext, TraceFlags
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.trace.status import StatusCode

texporter = grpcOTLPSpanExporter(
    endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
    insecure=True,
)

VERSION = os.environ.get("VERSION", "v2.0.0")
NAMESPACE = os.environ.get("NAMESPACE", "prompolicy")


def get_tracecontext(custom: str = False, headers: dict = {}) -> Context:
    def create_random():
        while True:
            span_id = hex(idg.RandomIdGenerator().generate_span_id())
            if len(span_id) == 18:
                break
        return (
            f"00-{hex(idg.RandomIdGenerator().generate_trace_id())[2:]}"
            + f"-{span_id[2:]}-01"
        )

    if custom == False:
        carrier = {"traceparent": headers.get("traceparent", create_random())}
    else:
        carrier = {"traceparent": custom}
    ctx = TraceContextTextMapPropagator().extract(carrier)
    if ctx == {}:
        ctx = context.get_current()
    return ctx


def params_to_trace(reqparams: Dict = {}) -> Dict:
    params = {}
    for p in reqparams:
        if isinstance(reqparams[p], (dict, MultiDict)):
            params[p] = str(dict(reqparams[p]))
        else:
            params[p] = reqparams[p]
    return params


def instrument(*args, **kwargs):

    SRV_NAME = os.environ.get("OTEL_SPAN_SERVICE", os.environ.get("HOSTNAME"))
    provider = TracerProvider(
        resource=Resource.create(
            {
                SERVICE_NAME: SRV_NAME,
                SERVICE_NAMESPACE: NAMESPACE,
                SERVICE_VERSION: VERSION,
            }
        )
    )
    simple_processor = BatchSpanProcessor(texporter)
    provider.add_span_processor(simple_processor)
    trace.set_tracer_provider(provider)
    AioHttpServerInstrumentor().instrument(
        trace_provider=provider, enable_commenter=True
    )
