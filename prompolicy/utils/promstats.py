import os
from functools import wraps
from time import time

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    multiprocess,
)
from prometheus_client.openmetrics.exposition import generate_latest

from prompolicy.tracing import *

# registry = CollectorRegistry()
# multiprocess.MultiProcessCollector(registry)


tracer = trace.get_tracer("proxy")

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total requests recieved from downstream",
    ["tenant", "method", "path", "downstream", "upstream"],
)
HTTP_RESPONSES_TOTAL = Counter(
    "http_responses_total",
    "Total responses send to downstream",
    ["tenant", "method", "path", "code", "downstream", "upstream"],
)
HTTP_REQUESTS_LATENCY = Histogram(
    "requests_latency_seconds",
    "Requests latency in seconds to downsteam",
    ["tenant", "method", "path", "downstream", "upstream"],
)

GRPC_CALLS_TOTAL = Counter(
    "grpc_requests_total", "Total requests created to upstream", ["tenant", "action"]
)
GRPC_CALLS_LATENCY = Histogram(
    "grpc_latency_seconds",
    "Requests latency in seconds from upstream",
    ["tenant", "entitites"],
)
POLICY_ITEMS = Counter(
    "policy_items_checked",
    "Items per requests to be checked",
    ["tenant", "kind", "tenant"],
)
VIOLATIONS_TOTAL = Counter(
    "violations_total", "Total violations from requests", ["tenant", "action", "kind"]
)


def generate_metrics():
    return generate_latest(REGISTRY)


def measure(func):
    @wraps(func)
    def measure(req, tenant, span):
        btime = time()
        rsp = func(req, tenant)
        etime = time()
        _ctx = span.get_span_context()
        traceparent = hex(_ctx.trace_id)[2:]
        uri = os.environ.get("PROMAPI", "http://127.0.0.1:9091")
        HTTP_REQUESTS_LATENCY.labels(
            str(tenant.name),
            req.method,
            req.path,
            "",
            uri,
        ).observe(btime - etime, exemplar={"trace_id": traceparent})
        HTTP_REQUESTS_LATENCY.labels(
            str(tenant.name),
            req.method,
            req.path,
            req.remote,
            uri,
        ).observe(btime - etime, exemplar={"trace_id": traceparent})
        HTTP_REQUESTS_TOTAL.labels(
            tenant.name,
            req.method,
            req.path,
            req.remote,
            uri,
        ).inc()
        return rsp

    return measure
