from typing import ByteString, Dict, Iterable, List, Self, Tuple
from concurrent.futures import ThreadPoolExecutor, wait

import urllib.parse
import logging
import os
from prompolicy.tracing import *
from prompolicy.utils.generators import Metric2Policy, MetricPrincipal, MetricsFactory
from prompolicy.utils.promql import PromQL
from prompolicy.utils.promstats import (
    GRPC_CALLS_LATENCY,
    GRPC_CALLS_TOTAL,
    VIOLATIONS_TOTAL,
)

from time import time
from ..exceptions import *
from . import PromFilter
from prompolicy.utils.logfilter import (
    FilteredLogger,
)

from opa import OPAClient

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

tracer = trace.get_tracer("proxy")


class OPAAPI(PromFilter):
    def __init__(
        self,
        uri: str = None,
        tenant: MetricPrincipal = None,
        action: str = None,
        tracecontext=None,
    ) -> Self:
        super(OPAAPI, self).__init__()
        self.uri = urllib.parse.urlparse(uri)
        self.tenant = tenant
        self.action = action
        self._ctx = tracecontext
        self._client = OPAClient(self.uri.geturl())
        self._policies = []

    @property
    def create_policies(self) -> None:
        for num, policy in enumerate(self.policies):
            self._client.save_policy(f"policy-{num}", policy)

    @property
    def policies(self) -> list[dict]:
        for policy in self._policies:
            yield policy

    def create_document(self, content: dict = {}) -> None:
        self._client.save_document(content["id"], content)

    def __len__(self) -> int:
        return len(list(self.policies))

    def filter(
        self,
        content: MetricsFactory,
        page: int = 0,
        pend: int = -1,
        policy: str = "abac.allow",
    ) -> Iterable:

        def iterator(entries):
            for entry in entries:
                try:
                    if isinstance(entry, PromQL):
                        for e in entry.to_dict():
                            yield e
                    else:
                        for e in entry.to_dict:
                            yield e
                except Exception as e:
                    raise Exception(str(e))

        btime = time()
        with tracer.start_as_current_span(
            "OPA Call",
            attributes={
                "tenant": self.tenant.name,
                "action": self.action,
                "groups": ",".join(self.tenant.groups),
            },
        ) as span:
            _ctx = span.get_span_context()
            self.traceparent = hex(_ctx.trace_id)[2:]
            for entry in iterator(content):
                #print(self.tenant.to_dict | {"metric": entry})
                if not self._client.check_policy(
                    policy, self.tenant.to_dict | {"metric": entry}
                ):
                    span.set_status(StatusCode.ERROR)
                    logger.debug(f"filtering resource {entry}", _ctx=_ctx, level=1)
                    span.add_event("filtering resource",
                            attributes=entry
                            )
                    VIOLATIONS_TOTAL.labels(
                        self.tenant.name,
                        self.action,
                        "metric",
                    ).inc(1.0, exemplar={"trace_id": self.traceparent})
                    yield entry.get("id")

    def paged_filter(
        self,
        content: MetricsFactory,
        page_size: int,
        workers: int = 10,
        policy="abac.allow",
    ):
        threads = []
        resource_list = list(content)
        size = len(resource_list)
        if size == 0:
            return None
        page = 0
        with ThreadPoolExecutor(max_workers=workers) as tpe:
            while True:
                pend = page + page_size if page + page_size <= size else size
                logger.debug(f"threading off for {page} -> {pend}", level=1)
                threads.append(
                    tpe.submit(self.filter, resource_list[page:pend], policy=policy)
                )
                page = page + page_size
                if page > size:
                    break
        wait(threads)

        for thread in threads:
            for res in thread.result():
                yield res

    def is_healthy(self) -> bool:
        try:
            if self._client.check_health():
                if len(self) == 0:
                    return False
        except:
            return False
        return True
