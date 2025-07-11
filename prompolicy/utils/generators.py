import base64
import logging
import os
from typing import ByteString, Dict, Iterable, List, Self, Tuple

import jwt
from cerbos.engine.v1 import engine_pb2
from cerbos.sdk.model import Principal, Resource, ResourceAction, ResourceList
from google.protobuf.struct_pb2 import ListValue, Value

from ..exceptions import *
from .logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)
from .promql import PromQL, PromQLFunctions

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)


class Metric2Cerbos(object):
    def __init__(
        self, metrics: List[PromQL] = None, tenant=None, action: str = "read"
    ) -> Self:
        self.tenant = tenant
        self.action = action
        self.metrics = metrics

    def what_am_i(self, metric: Dict) -> str:
        if metric.get("kind", False) is not False:
            if any([metric.get("kind") == "label", metric.get("name") == "label"]):
                return "label"
        elif metric.get("name") == "label":
            return "label"
        return "function" if metric.get("name") in PromQLFunctions else "metric"

    def __metric_to_grpc__(self, entry: Dict) -> Dict:
        attrs = dict(
            public=Value(bool_value=False),
            owner=Value(string_value="node"),
            kind=Value(string_value=self.what_am_i(entry)),
        )
        for k in entry:
            if isinstance(entry[k], bool):
                attrs[k] = Value(bool_value=entry[k])
            elif isinstance(entry[k], str):
                attrs[k] = Value(string_value=entry[k])
            elif isinstance(entry[k], list):
                buflist = ListValue()
                for e in entry[k]:
                    buflist.append(e)
                attrs[k] = Value(list_value=buflist)
            else:
                attrs[k] = Value(string_value=str(entry[k]))
        return attrs

    @property
    def to_grpc(self) -> engine_pb2.Resource:
        for metric in self.metrics.to_dict():
            yield engine_pb2.Resource(
                id=self.metrics.b64,
                kind=self.what_am_i(metric),
                attr=self.__metric_to_grpc__(metric),
            )

    @property
    def to_dict(self) -> List[Dict]:
        for metric in self.metrics.to_dict():
            yield metric

    def from_dict(self, metric: List[Dict]) -> Self:
        # [{'metric': {'cluster': 'us-east-1', 'cpu': '0', 'instance': 'server02.chester.at:9100', 'job': 'node', 'mode': 'idle'}}]
        raise ValueError("not implemented")
        self.metric = metric

    def __iter__(self):
        for m in self.metrics:
            yield m

    def __str__(self):
        return str(list(map(lambda x: x.to_dict(), self.metrics))[0])


class MetricsFactory(object):
    def __init__(self, metrics: List = [Metric2Cerbos]):
        self.metrics = []
        for m in metrics:
            if not isinstance(m, Metric2Cerbos):
                m = PromQL.parse(m)
                if m == None:
                    continue
            elif isinstance(m, Metric2Cerbos):
                self.metrics.append(m)
            else:
                print(f"{__class__.__name__} what am I {type(m)}")
                self.metrics.append(m)

    @classmethod
    def from_dict(cls, metrics: List = [Metric2Cerbos]) -> Self:
        def mapper(metrics):
            for x in metrics:
                if x.get("metric") == {}:
                    continue
                try:
                    yield Metric2Cerbos(PromQL.parse(x))
                except Exception:
                    pass

        return MetricsFactory(metrics=list(mapper(metrics)))

    def __len__(self):
        return len(list(self.metrics))

    @property
    def to_grpc(self) -> Iterable[Metric2Cerbos]:
        for m in self:
            for mm in m:
                if not isinstance(mm, Metric2Cerbos):
                    yield Metric2Cerbos(mm)
                else:
                    yield mm

    @property
    def to_dict(self) -> Iterable[Dict]:
        for m in self:
            for mm in m:
                if not isinstance(mm, Metric2Cerbos):
                    for mmd in Metric2Cerbos(mm).to_dict:
                        yield mmd
                elif isinstance(mm, dict):
                    yield mm
                else:
                    for mmd in mm.to_dict:
                        yield mmd

    def b64response(self, metric: List[PromQL], names: List[str] = []) -> ByteString:
        if not isinstance(metric, PromQL):
            # print(f"b64response input {metric}")
            if metric.get("name", False) is not False:
                metric["__name__"] = metric["name"]
                del metric["name"]
            elif all([metric.get("name", False) is False, names != []]):
                # hardcode first name for now
                metric["name"] = names[0]
            metric = PromQL.parse({"metric": metric})
            # print(f"b64response metric {base64.b64encode(str(metric.object.prettify()).encode('utf8'))}")
            # print(f"b64response metric {str(metric.object.prettify())}")
        return base64.b64encode(str(metric.object.prettify()).encode("utf8")).decode(
            "utf8"
        )

    def __iter__(self) -> Iterable[Metric2Cerbos]:
        for m in self.metrics:
            yield m


class MetricPrincipal(object):
    def __init__(self, token: str = None) -> Self:
        self.token = token

    @property
    def name(self) -> str:
        if self.token is None:
            logger.error(f"no token to derive principal name from", LF_BASE)
            raise MetricPrincipalException(f"no token to derive principal name from")
        return (
            self.token.get("preferred_username")
            if self.token.get("preferred_username", False) is not False
            else (
                self.token.get("username")
                if self.token.get("username", False) is not False
                else self.token.get("email", "anonymous")
            )
        )

    @property
    def groups(self) -> List[str]:
        if self.token is None:
            logger.error(f"no token to derive principal name from", LF_BASE)
            raise MetricPrincipalException(f"no token to derive principal name from")
        return (
            self.token.get("groups")
            if self.token.get("groups", False) is not False
            else (
                self.token.get("resource_access", {}).get("account", {}).get("roles")
                if self.token.get("resource_access", {})
                .get("account", {})
                .get("roles", False)
                is not False
                else ["user"]
            )
        )

    @classmethod
    def from_token(cls, content: str, do_time_check: bool = False) -> Self:
        try:
            # authentication: bearer xxxxx style
            token = jwt.JWT().decode(
                content.split()[-1], do_verify=False, do_time_check=do_time_check
            )
        except Exception as jwterr:
            try:
                # x-id-token: xxxx style
                token = jwt.JWT().decode(
                    content, do_verify=False, do_time_check=do_time_check
                )
            except Exception as jwterr:
                logger.error(f"no token to derive principal name from", LF_BASE)
                raise MetricPrincipalException(f"cannot determine token type {content}")
        return MetricPrincipal(token=token)

    @property
    def __token_to_dict__(self) -> Dict:
        attrs = {}
        for k in self.token:
            if isinstance(self.token[k], str):
                attrs[k] = Value(string_value=self.token[k])
        return attrs

    @property
    def to_grpc(self) -> engine_pb2.Principal:
        return engine_pb2.Principal(
            id=self.name,
            roles=self.groups,
            policy_version="20210210",
            attr=self.__token_to_dict__,
        )
