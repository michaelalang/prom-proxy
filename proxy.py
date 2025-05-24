#!/usr/bin/python3.13

from aiohttp import web
from aiohttp import client
import aiohttp
import asyncio
import logging
import json
import base64
import os
import urllib.parse
from copy import deepcopy
from time import time
import traceback

from collections import namedtuple
from cerbos.sdk.grpc.client import CerbosClient as CerbosClientGRPC

from multidict import MultiDictProxy, MultiDict

PAGESIZE = int(os.environ.get("PAGESIZE", 500))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 10))
TENANT_FILTER = "tenant"
CERBOSAPI = urllib.parse.urlparse(os.environ.get("CERBOSAPI", "http://localhost:3593"))
baseUrl = os.environ.get("PROMAPI", "http://127.0.0.1:9091")
LEARNING = bool(int(os.environ.get("LEARNING", False)))


from prompolicy.exceptions import (
    PermissionDenied,
    PromQLException,
    Learning,
    CerbosGRPCDown,
)
from prompolicy.utils.generators import adjust_headers, get_principal, b64encode
from prompolicy.utils.generators import remap_results
from prompolicy.utils.logfilter import (
    FilteredLogger,
    LF_BASE,
    LF_WEB,
    LF_RESPONSES,
    LF_MODEL,
    LF_POLICY,
)
from prompolicy.tenancy import require_tenancy, page_policy_resources, deduplicate
from prompolicy.promstats import (
    HTTP_REQUESTS_LATENCY,
    HTTP_REQUESTS_TOTAL,
    generate_metrics,
)
from prometheus_client import multiprocess, CollectorRegistry

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

registry = CollectorRegistry()
multiprocess.MultiProcessCollector(registry)


async def handler(req):
    t_starttime = time()
    slash = "" if req.path.startswith("/") else ""
    logger.debug(f"Req path = {req.path}", LF_WEB)

    def path_query(body):
        jbody = json.loads(body.decode("utf8"))
        try:
            original = len(jbody.get("data", {}).get("result", []))
            try:
                if (
                    jbody.get("data", {})
                    .get("result", [{"metric": {}}])[0]
                    .get("metric")
                    == {}
                ):
                    return body
            except Exception:
                pass
            if original > 0:
                logger.error(f"page_policy_resources with action 'response'")
                remove = list(
                    map(
                        lambda x: x,  # http version == x.resource.id
                        page_policy_resources(
                            deduplicate(
                                map(
                                    lambda y: remap_results(y),
                                    jbody.get("data").get("result"),
                                )
                            ),
                            tenant,
                            "response",
                        ),
                    )
                )
                newresult = list(
                    filter(
                        lambda x: not b64encode(x) in remove,
                        map(
                            lambda y: remap_results(y, values=True),
                            jbody.get("data").get("result"),
                        ),
                    )
                )
                if not LEARNING:
                    jbody["data"]["result"] = newresult
                if len(remove) > 0:
                    logger.info(
                        f"[{tenant.id}] removed {len(remove)} new {len(newresult)} original {original}",
                        LF_BASE,
                    )
                if len(newresult) == 0:
                    if LEARNING:
                        raise Learning()
                    raise PermissionDenied()
                body = json.dumps(jbody).encode("utf8")
        except Learning as permerr:
            raise permerr
        except PermissionDenied as permerr:
            raise permerr
        except Exception as proxyerr:
            logger.error(f"{req.path} Exception {proxyerr}", LF_BASE)
            traceback.print_exception(proxyerr)
        return body

    def path_query_range(body):
        jbody = json.loads(body.decode("utf8"))
        try:
            original = len(jbody.get("data", {}).get("result", []))
            try:
                if (
                    jbody.get("data", {})
                    .get("result", [{"metric": {}}])[0]
                    .get("metric")
                    == {}
                ):
                    return body
            except:
                pass
            if original > 0:
                logger.error(f"page_policy_resources with action 'response'", LF_MODEL)
                remove = list(
                    map(
                        lambda x: x,  # http version == x.resource.id
                        page_policy_resources(
                            deduplicate(
                                map(
                                    lambda y: remap_results(y),
                                    jbody.get("data").get("result"),
                                )
                            ),
                            tenant,
                            "response",
                        ),
                    )
                )
                newresult = list(
                    filter(
                        lambda x: not b64encode(x) in remove,
                        map(
                            lambda y: remap_results(y, values=True),
                            jbody.get("data").get("result"),
                        ),
                    )
                )
                if not LEARNING:
                    jbody["data"]["result"] = newresult
                if len(remove) > 0:
                    logger.info(
                        f"[{tenant.id}] removed {len(remove)} new {len(newresult)} original {original}",
                        LF_BASE,
                    )
                if len(newresult) == 0:
                    if LEARNING:
                        raise Learning()
                    raise PermissionDenied()
                body = json.dumps(jbody).encode("utf8")
        except Learning as permerr:
            raise permerr
        except PermissionDenied as permerr:
            raise permerr
        except Exception as proxyerr:
            logger.error(f"{req.path} Exception {proxyerr}", LF_BASE)
        return body

    def path_label_values(body):
        return body
        jbody = json.loads(body.decode("utf8"))

        try:
            logger.info(f"path_label_values {len(body)}", LF_MODEL)
            original = len(jbody.get("data"))
            if original > 0:
                remove = list(
                    map(
                        lambda x: json.loads(base64.b64decode(x))
                        .get("metric", {})
                        .get("__name__"),  # http version == x.resource.id,
                        page_policy_resources(
                            list(
                                map(
                                    lambda x: {"metric": {"__name__": x}},
                                    jbody.get("data"),
                                )
                            ),
                            tenant,
                            action="read",
                        ),
                    )
                )
                newresult = list(
                    filter(
                        lambda x: not x in remove,
                        jbody.get("data"),
                    )
                )
                logger.info(f"path_label_values {len(newresult)}")
                if not LEARNING:
                    jbody["data"] = newresult
                if len(remove) > 0:
                    logger.info(
                        f"LabelValues [{tenant.id}] removed {len(remove)} new {len(newresult)} original {original}",
                        LF_BASE,
                    )
                if len(newresult) == 0:
                    if LEARNING:
                        raise Learning()
                    raise PermissionDenied()
                body = json.dumps(jbody).encode("utf8")
        except Learning as permerr:
            raise permerr
        except PermissionDenied as permerr:
            raise permerr
        except Exception as proxyerr:
            logger.error(f"{req.path} Exception {proxyerr}", LF_BASE)
        return body

    def path_tenant_values(body):
        jbody = json.loads(body.decode("utf8"))

        try:
            original = len(jbody.get("data"))
            if original > 0:
                remove = list(
                    map(
                        lambda x: x,  # http version == x.resource.id,
                        page_policy_resources(jbody.get("data"), tenant),
                    )
                )
                newresult = list(
                    filter(
                        lambda x: not b64encode(x) in remove,
                        jbody.get("data"),
                    )
                )
                if not LEARNING:
                    jbody["data"] = newresult
                if len(remove) > 0:
                    logger.info(
                        f"[{tenant.id}] removed {len(remove)} new {len(newresult)} original {original}",
                        LF_BASE,
                    )
                if len(newresult) == 0:
                    if not LEARNING:
                        raise Learning()
                    raise PermissionDenied()
                body = json.dumps(jbody).encode("utf8")
        except Learning as permerr:
            raise permerr
        except PermissionDenied as permerr:
            raise permerr
        except Exception as proxyerr:
            logger.error(f"{req.path} Exception {proxyerr}", LF_BASE)
        return body

    reqdata = await req.post()
    if any(
        [
            str(req.path)
            in (
                "/api/v1/series",
                "/api/v1/metadata",
                "/-/healthy",
                "-/ready",
                "/api/v1/status/buildinfo",
            ),
            str(req.path).startswith("/api/v1/label"),
        ]
    ):
        logger.info(f"Whitelist for {req.path} {reqdata}", LF_WEB)
        tenant, data = get_principal("anonymous-allowed"), reqdata

    try:
        tenant, data = require_tenancy(reqdata, req)
    except PromQLException as pqlerr:
        logger.error(f"Proxy1 PromQLException {pqlerr}", LF_BASE)
        logger.error(f"reqdata = {await req.post()}", LF_MODEL)
        # don't fail on parsing errors for now
        tenant = get_principal("anonymous-allowed")
        data = reqdata.copy()
        # return web.Response(status=pqlerr.code, body=pqlerr.msg)
    except Learning:
        logger.error(
            f"PermissionDenied require valid Tenant {req} {dict(req.query.copy())} {dict(reqdata)}",
            LF_BASE,
        )
    except PermissionDenied as permerr:
        logger.error(
            f"PermissionDenied require valid Tenant {req} {dict(req.query.copy())} {dict(reqdata)}",
            LF_BASE,
        )
        return web.Response(status=permerr.code, body=permerr.msg)
    except CerbosGRPCDown as permerr:
        logger.error(f"Cerbos GRPC down {permerr}", LF_BASE)
        return web.Response(status=permerr.code, body=permerr.msg)
    except Exception as err:
        traceback.print_exception(err)
    try:
        if all(
            [
                req.query.get("query") != MultiDictProxy(MultiDict()),
                req.query.get("query") != MultiDict(),
            ]
        ):
            params = reqdata.copy()
        else:
            params = req.query.get("query")
        logger.debug(f"params from data {params}", LF_POLICY)
    except Exception as parerr:
        params = None

    reqparams = {
        "method": req.method,
        "url": f"{baseUrl}{slash}{str(req.path)}",
        "allow_redirects": True,
        "ssl": False,
    }

    if req.query == MultiDictProxy(MultiDict()):
        if data != None:
            reqparams["data"] = (
                urllib.parse.urlencode(dict(data)).encode("utf8")
                if data != MultiDictProxy(MultiDict())
                else MultiDictProxy(MultiDict())
            )
            if reqparams["data"] == MultiDictProxy(MultiDict()):
                del reqparams["data"]
    elif await req.read() in [b"", MultiDictProxy(MultiDict())]:
        reqparams["params"] = (
            params
            if req.query.get("query") != MultiDictProxy(MultiDict())
            else MultiDictProxy(MultiDict())
        )
        if reqparams["params"] == MultiDictProxy(MultiDict()):
            del reqparams["params"]
    if params in ["", MultiDictProxy(MultiDict()), MultiDict()]:
        reqparams["params"] = params
    if all(
        [
            reqparams.get("params", False) not in (False, MultiDictProxy(MultiDict())),
            reqparams.get("data", False) not in (False, MultiDictProxy(MultiDict())),
            req.headers.get("Content-Type") == "application/x-www-form-urlencoded",
        ]
    ):
        logger.debug(f"reqparams {reqparams}", LF_MODEL)
        del reqparams["params"]

    reqparams["headers"] = adjust_headers(req.headers)

    starttime = time()
    async with client.request(**reqparams) as res:
        body = await res.read()
        logger.info(
            f"[{tenant.id}] response from upstream {reqparams.get('url')} {res.status}",
            LF_WEB,
        )
        logger.debug(f"upstream response {body}", LF_RESPONSES)
        status = res.status
        headers = adjust_headers(res.headers.copy())
        if res.status >= 300:
            logger.debug(f"upstrem response {body}", LF_RESPONSES)
            logger.debug(f"recieved from downstream {await req.post()}", LF_RESPONSES)
            status = res.status
        if req.path == "/api/v1/query":
            try:
                body = path_query(body)
                status = res.status
            except Learning as permerr:
                status = res.status
            except PermissionDenied as permerr:
                status = permerr.code
                body = permerr.msg
            except Exception as err:
                traceback.print_exception(err)
            headers = adjust_headers(res.headers.copy())
            # ToDO
            # elif req.path.startswith("/api/v1/label"):
            #    headers = adjust_headers(res.headers.copy())
            #    status = res.status
            #    logger.debug(f"buildinfo downstream response {body}", LF_L4)
            # elif req.path == "/api/v1/metadata":
            #    try:
            #        body = path_label_values(body)
            #        status = res.status
            #    except Learning as permerr:
            #        status = res.status
            #    except PermissionDenied as permerr:
            #        status = permerr.code
            #        body = permerr.msg
            #    headers = adjust_headers(res.headers.copy())
        elif req.path == "/api/v1/query_range":
            try:
                body = path_query_range(body)
                status = res.status
            except Learning as permerr:
                status = res.status
            except PermissionDenied as permerr:
                status = permerr.code
                body = permerr.msg
            except Exception as err:
                traceback.print_exception(err)
            headers = adjust_headers(res.headers.copy())
            # elif req.path == "/api/v1/status/buildinfo":
            #    headers = adjust_headers(res.headers.copy())
            #    status = res.status
            #    logger.debug(f"buildinfo downstream response {body}", LF_L4)
            # else:
            #    headers = adjust_headers(res.headers.copy())
            #    body = await res.read()
            #    status = res.status
        # logger.debug(f"downstream response {body}", LF_RESPONSES)
        stoptime = time()
        HTTP_REQUESTS_LATENCY.labels(
            tenant.id, req.method, req.path, "", baseUrl
        ).observe(
            stoptime - starttime  # , {"trace_id": traceid}
        )
        HTTP_REQUESTS_LATENCY.labels(
            tenant.id, req.method, req.path, req.remote, ""
        ).observe(
            stoptime - t_starttime  # , {"trace_id": traceid}
        )
        HTTP_REQUESTS_TOTAL.labels(
            tenant.id, req.method, req.path, req.remote, baseUrl
        ).inc()
        return web.Response(
            status=status,
            headers=headers,
            body=body,
        )


async def health(req):
    try:
        async with client.request(
            "GET",
            f"{baseUrl}/-/healthy",
            allow_redirects=True,
            ssl=True,
        ) as res:
            if not res.status == 200:
                return web.Response(
                    status=res.status,
                    body=res.body,
                )
    except Exception as promerr:
        logger.error(f"HealthState Prometheus not healthy {promerr}")
        return web.Response(
            status=503,
            body=str(promerr),
        )

    try:
        if CERBOSAPI.scheme == "grpc":
            with CerbosClientGRPC(CERBOSAPI.netloc, tls_verify=False) as cerb:
                resp = cerb.server_info()
            with CerbosClient(host=CERBOSAPI.geturl()) as cerb:
                resp = cerb.is_healthy()
    except Exception as cerberr:
        logger.error(f"HealthState Cerbos not healthy {cerberr}")
        return web.Response(
            status=503,
            body=str(cerberr),
        )
    return web.Response(status=200, body="OK")


async def metrics(req):
    return web.Response(
        status=200,
        headers={
            "Content-Type": "application/openmetrics-text; version=1.0.0; charset=utf-8",
            "MimeType": "application/openmetrics-text; version=1.0.0; charset=utf-8",
        },
        body=generate_metrics(registry),
    )


async def app_factory():
    app = web.Application()
    app.router.add_route("*", "/health", health)
    app.router.add_route("GET", "/metrics", metrics)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


if __name__ == "__main__":
    print(f"Running on {CERBOSAPI}")
    web.run_app(app_factory(), port=int(os.environ.get("PORT", 3985)))
