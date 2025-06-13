import base64
import urllib.parse
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
from prompolicy.utils.generators import Metric2Cerbos, MetricPrincipal, MetricsFactory
from prompolicy.utils.promql import PromQL
from prompolicy.utils.promstats import (
    GRPC_CALLS_LATENCY,
    GRPC_CALLS_TOTAL,
    VIOLATIONS_TOTAL,
)

from ..exceptions import *
from . import PromFilter


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
            content = [Metric2Cerbos(content).to_grpc]
        else:
            content = [content.to_grpc]
        if content == []:
            return

        def iterater(content: Metric2Cerbos, span=None) -> engine_pb2.Resource:
            for c in content:
                if isinstance(c, engine_pb2.Resource):
                    span.add_event(f"{c.id} {c.kind}", attributes={"resource": str(c)})
                    # print(f"c {c}")
                    yield c
                elif isinstance(c, list):
                    for cc in c:
                        # print(f"cc {cc}")
                        yield cc
                elif isinstance(c, Generator):
                    for cc in c:
                        # print(f"cc {cc}")
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
                span.set_status(StatusCode.ERROR)
                yield x

        btime = time()
        with tracer.start_as_current_span(
            "Cerbos Call",
            # context=self._ctx,
            attributes={
                "tenant": self.tenant.name,
                "action": self.action,
                "groups": ','.join(self.tenant.groups),
                },
        ) as span:
            _ctx = span.get_span_context()
            self.traceparent = hex(_ctx.trace_id)[2:]

            with self._client(self.uri.netloc, tls_verify=False) as cerb:
                GRPC_CALLS_TOTAL.labels(self.tenant.name, self.action).inc()
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
                    yield r.resource.id
                # for r in list(
                #    map(
                #        lambda y: y,
                #        list(
                #            filter(lambda x: not is_allowed(x, self.action), resp.results)
                #        ),
                #    )
                # ):
                # print(r.resource.id)
                #    yield r.resource.id
            etime = time()
            GRPC_CALLS_LATENCY.labels(self.tenant.name, len(content)).observe(
                btime - etime, exemplar={"trace_id": self.traceparent}
            )

    def paged_filter(self, content: MetricsFactory, page_size: int, workers: int = 10):
        threads = []
        # print(f"PAGED_FILTER calling on {len(content)}")
        # print(f"PAGED_FILTER content {list(content)}")
        resource_list = ResourceList(resources=list(content))
        size = len(resource_list.resources)
        if size == 0:
            return None
        page = 0

        with ThreadPoolExecutor(max_workers=workers) as tpe:
            while True:
                pend = page + page_size if page + page_size <= size else size
                # print(f"threading off for {page} -> {pend}")
                threads.append(
                    tpe.submit(self.filter, resource_list.resources[page:pend])
                )
                page = page + page_size
                if page > size:
                    break
        wait(threads)

        for thread in threads:
            for res in thread.result():
                # print(f"{thread} result {res}")
                yield res
