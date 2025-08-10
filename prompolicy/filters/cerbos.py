import base64
import urllib.parse
import os
import logging
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor, wait
from functools import wraps
from time import time
from typing import ByteString, Dict, Iterable, List, Self, Tuple

from cerbos.engine.v1 import engine_pb2
from cerbos.request.v1 import request_pb2
from cerbos.sdk.client import CerbosClient
from cerbos.sdk.grpc.client import CerbosClient as CerbosClientGRPC
from cerbos.sdk.grpc.utils import is_allowed
from cerbos.sdk.model import Principal, ResourceList
from grpc._channel import _InactiveRpcError

from prompolicy.tracing import *
from prompolicy.utils.generators import Metric2Policy, MetricPrincipal, MetricsFactory
from prompolicy.utils.promql import PromQL
from prompolicy.utils.promstats import (
    GRPC_CALLS_LATENCY,
    GRPC_CALLS_TOTAL,
    VIOLATIONS_TOTAL,
)

from ..exceptions import *
from . import PromFilter
from prompolicy.utils.logfilter import (
    FilteredLogger,
)

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)


def measure(func):
    @wraps(func)
    def measure(
        content: MetricsFactory, page: int = 0, pend: int = -1
    ) -> Iterable[engine_pb2.Resource]:
        btime = time()
        rsp = func(content, page, pend)
        etime = time()
        # GRPC_CALLS_LATENCY.labels(tenant.tenant.name, 1
        # ).observe(
        #    btime - etime  # , exemplar={"trace_id": traceid}
        # )
        return rsp

    return measure


tracer = trace.get_tracer("proxy")


class CerbosAPI(PromFilter):
    def __init__(
        self,
        uri: str = None,
        tenant: MetricPrincipal = None,
        action: str = None,
        tracecontext=None,
    ) -> Self:
        super(CerbosAPI, self).__init__()
        self.uri = urllib.parse.urlparse(uri)
        self.tenant = tenant
        self.action = action
        self._ctx = tracecontext
        if self.uri.scheme == "grpc":
            self._client = CerbosClientGRPC
        elif self.uri.scheme in ["http", "https"]:
            self._client = CerbosClient

    @property
    def is_healthy(self) -> bool:
        if self.uri.scheme == "grpc":
            ccall = "server_info"
        elif self.uri.scheme in ["http", "https"]:
            ccall = "is_healthy"

        with self._client(self.uri.netloc, tls_verify=False) as cerb:
            resp = getattr(cerb, ccall)()
            return resp

    def filter(
        self, content: MetricsFactory, page: int = 0, pend: int = -1
    ) -> Iterable[engine_pb2.Resource]:
        if isinstance(content, list):
            ncontent = []
            for c in map(lambda x: list(x.to_grpc), content):
                for sc in c:
                    ncontent.append(sc)
            content = ncontent
        elif isinstance(content, PromQL):
            content = [Metric2Policy(content).to_grpc]
        else:
            content = [content.to_grpc]
        if content == []:
            return

        def iterater(content: Metric2Policy, span=None) -> engine_pb2.Resource:
            for c in content:
                if isinstance(c, engine_pb2.Resource):
                    span.add_event(f"{c.id} {c.kind}", attributes={"resource": str(c)})
                    logger.debug(f"c {c}", level=9)
                    if c.kind in ("alert", "metric"):
                        yield c
                elif isinstance(c, list):
                    for cc in c:
                        span.add_event(
                            f"{cc.id} {cc.kind}", attributes={"resource": str(cc)}
                        )
                        logger.debug(f"cc {cc}", level=9)
                        if cc.kind in ("alert", "metric"):
                            yield cc
                else:  # isinstance(c, generator):
                    for cc in c:
                        span.add_event(
                            f"{cc.id} {cc.kind}", attributes={"resource": str(cc)}
                        )
                        logger.debug(f"cc {cc}", level=9)
                        if cc.kind in ("alert", "metric"):
                            yield cc

        def iterater_response(resp, span) -> Iterable[str]:
            for x in filter(lambda x: not is_allowed(x, self.action), resp.results):
                span.add_event(
                    "Policy rejected",
                    attributes={
                        "resource_id": base64.b64decode(
                            x.resource.id.encode("utf8")
                        ).decode("utf8"),
                        "resource_kind": x.resource.kind,
                        "action": self.action,
                        "tenant": self.tenant.name,
                    },
                )
                VIOLATIONS_TOTAL.labels(
                    self.tenant.name, self.action, x.resource.kind
                ).inc(1.0, exemplar={"trace_id": self.traceparent})
                logger.debug(f"filtering resource {x}", level=9)
                span.set_status(StatusCode.ERROR)
                yield x

        btime = time()
        with tracer.start_as_current_span(
            "Cerbos Call",
            attributes={
                "tenant": self.tenant.name,
                "action": self.action,
                "groups": ",".join(self.tenant.groups),
            },
        ) as span:
            _ctx = span.get_span_context()
            self.traceparent = hex(_ctx.trace_id)[2:]

            with self._client(self.uri.netloc, tls_verify=False) as cerb:
                GRPC_CALLS_TOTAL.labels(self.tenant.name, self.action).inc()
                span.add_event(
                    f"tenant {self.tenant.name}",
                    attributes={
                        "name": self.tenant.name,
                        "groups": ",".join(self.tenant.groups),
                    },
                )
                try:
                    resp = cerb.check_resources(
                        principal=self.tenant.to_grpc,
                        resources=list(
                            map(
                                lambda x: request_pb2.CheckResourcesRequest.ResourceEntry(
                                    actions=[self.action], resource=x
                                ),
                                iterater(content, span),
                            )
                        ),
                    )
                    for r in iterater_response(resp, span):
                        span.set_status(StatusCode.ERROR)
                        #span.add_event(
                        #    "filtering resource",
                        #    attributes={
                        #        "resource": base64.b64decode(
                        #            r.resource.id.encode("utf8")
                        #        ),
                        #        "tenant": self.tenant.name,
                        #        "action": self.action,
                        #    },
                        #)
                        logger.debug(f"filtering resource {r}", _ctx=_ctx, level=1)
                        yield r.resource.id
                except Exception as cerr:
                    span.record_exception(cerr)
                    logger.error(f"Cerbos Call exception {cerr}", _ctx=_ctx, level=1)
            etime = time()
            GRPC_CALLS_LATENCY.labels(self.tenant.name, len(content)).observe(
                btime - etime, exemplar={"trace_id": self.traceparent}
            )

    def paged_filter(self, content: MetricsFactory, page_size: int, workers: int = 10):
        threads = []
        resource_list = ResourceList(resources=list(content))
        size = len(resource_list.resources)
        if size == 0:
            return None
        page = 0

        with ThreadPoolExecutor(max_workers=workers) as tpe:
            while True:
                pend = page + page_size if page + page_size <= size else size
                logger.debug(f"threading off for {page} -> {pend}", level=1)
                threads.append(
                    tpe.submit(self.filter, resource_list.resources[page:pend])
                )
                page = page + page_size
                if page > size:
                    break
        wait(threads)

        for thread in threads:
            for res in thread.result():
                yield res
