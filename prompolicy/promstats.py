from prometheus_client import Counter, Histogram
from prometheus_client.openmetrics.exposition import generate_latest

from functools import wraps
from time import time

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


def generate_metrics(registry):
    return generate_latest(registry)

