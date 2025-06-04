import logging
import os
from functools import wraps
from typing import ByteString, Dict, Iterable, List, Self, Tuple

from aiohttp import web

from prompolicy.tracing import *

from ..exceptions import *
from .generators import MetricPrincipal
from .logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

tracer = trace.get_tracer("proxy")


def adjust_headers(headers: Dict) -> Dict:
    reqheaders = headers.copy()
    for h in (
        "Transfer-Encoding",
        "Content-Length",
        "Content-Encoding",
        "Accept-Encoding",
        "Origin",
        "Referer",
        "Host",
        "Vary",
    ):
        try:
            del reqheaders[h]
        except Exception as e:
            pass
    return reqheaders


def remap_results(
    dataset: List[Dict], values: bool = False, names: List[str] = []
) -> Iterable[Dict]:
    def remap_one(data):
        try:
            newdata = {"metric": {}}
            if len(names) > 0:
                if data["metric"].get("__name__", False) is False:
                    newdata["metric"]["__name__"] = names[0]
            for k in data.get("metric"):
                newdata["metric"][k] = data["metric"][k]
            if values:
                try:
                    newdata["values"] = data["values"]
                except KeyError as kerr:
                    try:
                        newdata["value"] = data["value"]
                    except KeyError as kerr:
                        logger.debug(f"remap_results data keys {data.keys()}", LF_MODEL)
                        raise KeyError(kerr)
            return newdata
        except AttributeError:
            return data

    if isinstance(dataset, list):
        for data in dataset:
            yield remap_one(data)
    else:
        yield remap_one(dataset)


def get_tenant(func) -> web.Response | MetricPrincipal:
    @wraps(func)
    def authorization(req: web.Request) -> web.Response | MetricPrincipal:
        headers = req.headers.copy()
        with tracer.start_as_current_span(
            "authorization",
        ) as span:
            try:
                tenant = MetricPrincipal.from_token(
                    headers.get("x-id-token"), headers.get("Authorization")
                )
                span.set_status(StatusCode.OK)
            except MetricPrincipalException as e:
                span.set_status(StatusCode.ERROR)
                span.record_exception(error)
                return web.Response(body=e.msg, status=e.code)
            rsp = func(req, tenant, span)
            return rsp

    return authorization
