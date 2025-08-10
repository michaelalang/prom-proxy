import logging
import os
from functools import wraps
from typing import ByteString, Dict, Iterable, List, Self, Tuple

from aiohttp import web

from prompolicy.tracing import *

from ..exceptions import *
from .generators import MetricPrincipal
from .promql import PromQL
from .logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)
import base64

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
            logger.debug("Cannot delete header {h}", level=999)
    return reqheaders


def enforce_results(
    dataset: List[Dict], values: bool = False, pql: List[PromQL] = []
) -> Iterable[Dict]:
    def remap_one(data):
        newdata = {"metric": {}}
        for k in data.get("metric"):
            newdata["metric"][k] = data["metric"][k]
        if pql != []:
            for p in pql:
                pqld = p.to_dict()[0]
                for k in pqld:
                    if k == "name":
                        continue
                    if newdata["metric"].get(k, False) == False:
                        newdata["metric"][k] = pqld[k]
        if values == True:
            try:
                newdata["values"] = data["values"]
            except KeyError as kerr:
                try:
                    newdata["value"] = data["value"]
                except KeyError as kerr:
                    logger.debug(f"remap_results data keys {data.keys()}", level=3)
                    raise KeyError(kerr)
        return data

    if isinstance(dataset, list):
        for data in dataset:
            yield remap_one(data)
    else:
        yield remap_one(dataset)


def remap_results(
    dataset: List[Dict], values: bool = False, names: List[str] = [], pql: PromQL = None
) -> Iterable[Dict]:
    def remap_one(data):
        try:
            newdata = {
                "metric": {}
            }  # , "remapid": base64.b64encode(str(data["metric"]).encode("utf8"))}
            try:
                if len(pql.get_names()) > 0:
                    if data["metric"].get("__name__", False) is False:
                        newdata["metric"]["__name__"] = pql.get_names()[0]
            except:
                pass
            for k in data.get("metric"):
                newdata["metric"][k] = data["metric"][k]
            if values:
                try:
                    newdata["values"] = data["values"]
                except KeyError as kerr:
                    try:
                        newdata["value"] = data["value"]
                    except KeyError as kerr:
                        logger.debug(f"remap_results data keys {data.keys()}", level=3)
                        raise KeyError(kerr)
            if pql != None:
                for label in pql.to_dict():
                    for k in label:
                        if k == "name":
                            continue
                        if newdata["metric"].get(k, False) == False:
                            newdata["metric"][k] = label[k]
            # print(f"remapped data {newdata}")
            return newdata
        except AttributeError:
            #print(f"Attribute error on data {data}")
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
            except MetricPrincipalException as error:
                span.set_status(StatusCode.ERROR)
                span.record_exception(error)
                return web.Response(body=error.msg, status=error.code)
            rsp = func(req, tenant, span)
            return rsp

    return authorization
