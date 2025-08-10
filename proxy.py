#!/usr/bin/python
import asyncio
import base64
import json
import logging
import os
import re

import aiohttp
from aiohttp import client, web
from multidict import MultiDict, MultiDictProxy

from prompolicy.exceptions import *
from prompolicy.filters.cerbos import CerbosAPI
from prompolicy.filters.opa import OPAAPI
from prompolicy.tracing import *
from prompolicy.utils.generators import Metric2Policy, MetricsFactory
from prompolicy.utils.logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)
from prompolicy.utils.promql import PromQL, PromQL_safe
from prompolicy.utils.promstats import generate_metrics, measure
from prompolicy.utils.webrequests import (
    adjust_headers,
    enforce_results,
    get_tenant,
    remap_results,
)

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

PROMURL = os.environ.get("PROMAPI", "http://127.0.0.1:9091")
POLICYAPI = os.environ.get("POLICYAPI", "http://localhost:3593")

APIINT = CerbosAPI if os.environ.get("POLICYENGINE", "CERBOS") == "CERBOS" else OPAAPI

instrument()
tracer = trace.get_tracer("proxy")


@web.middleware
async def opentelemetry(request, handler):
    _ctx = get_tracecontext(request.headers.copy())

    # logger.info(f"Request Headers {request.headers.copy()}", _ctx=_ctx)
    tracer = trace.get_tracer("aiohttp.server")
    with tracer.start_as_current_span(
        "aiohttp.handler", kind=trace.SpanKind.SERVER
    ) as span:
        return await handler(request)


async def metrics(req):
    return web.Response(
        status=200,
        headers={
            "Content-Type": "application/openmetrics-text",
            "MimeType": "application/openmetrics-text",
        },
        body=generate_metrics(),
    )


async def health(req):
    try:
        async with client.request(
            "GET",
            f"{PROMURL}/-/healthy",
            allow_redirects=True,
            ssl=True,
        ) as res:
            if not res.status == 200:
                return web.Response(
                    status=res.status,
                    body=res.body,
                )
    except Exception as promerr:
        logger.error(f"HealthState Prometheus not healthy {promerr}", level=0)
        return web.Response(
            status=503,
            body=str(promerr),
        )

    try:
        cerb = APIINT(POLICYAPI).is_healthy
        logger.error(f"{APIINT} {cerb}", level=0)
    except Exception as cerberr:
        logger.error(f"HealthState Cerbos not healthy {cerberr}", level=0)
        return web.Response(
            status=503,
            body=str(cerberr),
        )
    return web.Response(status=200, body="OK")


def inject_cluster(data: dict = {}, enforcing: list = [str], _ctx=None) -> dict:
    try:
        pql = PromQL.parse(data.get("query", data.get("match[]")))
    except Exception as perr:
        try:
            pql = PromQL.parse(data.get("data", data.get("match[]")))
        except Exception as perr:
            # logger.error(f"inject_cluster Exception {perr}")
            # logger.error(f"data = {data}")
            return data
    logger.debug(f"Enforcing injects {enforcing}", _ctx=_ctx)
    for enf in enforcing:
        enforce = PromQL.parse("up{" + enf + "}")
        pql = pql.enforce_new(enforce)
        logger.info(
            f"injection PQL {enf}",
            _ctx=_ctx,
            level=9,
        )
    try:
        pql1 = PromQL.parse(data.get("query"))
        if isinstance(pql, PromQL):
            pql = pql.to_str
        data["query"] = pql
    except:
        if isinstance(pql, PromQL):
            pql = pql.to_str
        data["match[]"] = pql
    logger.debug(f"enforced success {pql}", _ctx=_ctx)
    return data


async def parsequeries(data, tenant, action, enforcing, _ctx):
    if data == None:
        return data
    # if we want to enforce !!!
    try:
        data = inject_cluster(data, enforcing, _ctx)
    except Exception as injerr:
        with tracer.start_as_current_span(
            "exception",
            attributes={
                "function": "inject_cluster",
                "data": str(data),
                "enforcing": str(enforcing),
            },
        ) as span:
            logger.debug(
                f"ignoring injection due to error {injerr} {get_traceparent(_ctx).header}",
                _ctx=_ctx,
                level=1,
            )
            span.set_status(StatusCode.ERROR)
            span.record_exception(injerr)
    try:
        metric = Metric2Policy(
            PromQL.parse(data.get("query", data.get("match[]"))), tenant, action
        )
    except (AttributeError, PromQLException):
        return data
    api = APIINT(POLICYAPI, tenant=tenant, action=action, tracecontext=_ctx)
    for perr in api.filter(metric):
        logger.debug(f"Permission Denied {tenant.name} {action}", _ctx=_ctx, level=1)
        raise PermissionDenied()
    return data


async def parseresponse(data, tenant, action, reqparams, enforcing, _ctx):
    def map_enforcing(enforcing):
        for e in enforcing:
            try:
                # print(f"yield {e}")
                yield PromQL.parse(e)
            except:
                try:
                    # print("yield up{" + e + "}")
                    yield PromQL.parse("up{" + e + "}")
                except Exception as ex:
                    logger.debug(
                        f"ignoring {e} from enforcing {ex}", _ctx=_ctx, level=1
                    )

    def enforce(pql, enforcing):
        for enf in map_enforcing(enforcing):
            pql = pql.enforce_new(enf).to_str
            logger.info(
                f"Enforced injection to PQL {pql}",
                _ctx=_ctx,
                level=3,
            )
        return PromQL.parse(pql)

    try:
        if "/api/v1/label/" in reqparams.get("url", ""):
            data = json.loads(data)
            newdata = []
            for env in map_enforcing(enforcing):
                for m in env.matchers.to_dict():
                    if reqparams.get("url", "").endswith(f"/api/v1/label/{m}/values"):
                        for v in data["data"]:
                            if any(
                                mre.match(v)
                                for mre in [
                                    re.compile(mve)
                                    for mve in list(env.matchers.to_dict().values())
                                ]
                            ):
                                newdata.append(v)
                            else:
                                logger.info(f"Removing {v}", _ctx=_ctx, level=3)
            if newdata != []:
                return json.dumps({"status": "success", "data": newdata})
            else:
                return json.dumps(data)
    except Exception as perr:
        logger.error(
            f"Enforcing labels, {perr}",
            level=1,
            _ctx=_ctx,
        )
        try:
            return json.dumps(data)
        except:
            return data
    try:
        qcall = PromQL.parse(reqparams.get("data").get("query"))
        qcall = enforce(qcall, enforcing)
    except Exception as perr:
        logger.error(
            f"Enforcing failed, qcall {reqparams} enforcing {enforcing}",
            level=1,
            _ctx=_ctx,
        )
        qcall = []
    if data == None:
        return data
    try:
        mdata = json.loads(data).get("data", False)
        if mdata == False:
            mdata = json.loads(data).get("result")
    except Exception:
        return data
    try:
        rspdata = MetricsFactory.from_dict(
            remap_results(mdata.get("result"), pql=qcall)
        )
    except AttributeError as err:
        logger.error(f"AttributeError for metrics on result {err}", level=0, _ctx=_ctx)
        return data
    except Exception as err:
        logger.error(f"Exception for metrics on result {err}", level=0, _ctx=_ctx)
        logger.debug(mdata, level=1, _ctx=_ctx)
    api = APIINT(POLICYAPI, tenant=tenant, action=action, tracecontext=_ctx)
    removes = list(api.paged_filter(rspdata, page_size=500, workers=10))
    newdata = []
    is_rejected = False

    logger.debug(f"removes: {removes}", _ctx=_ctx, level=9)
    with tracer.start_as_current_span(
        "filtering",
        attributes={
            "tenant": tenant.name,
            "action": action,
            "groups": ",".join(tenant.groups),
        },
    ) as span:
        try:
            for x in mdata.get("result"):
                if x.get("metric", {}) == {}:
                    if len(removes) > 0:
                        is_rejected = True
                        continue
                    newdata.append(x)
                    continue
                try:
                    xx = x.get("metric")
                    xx["name"] = xx.get("__name__", names[0])
                    del xx["__name__"]
                except Exception as xe:
                    xx = x.get("metric")
                if not any(
                    [
                        rspdata.b64response(x.get("metric")) in removes,
                        rspdata.b64response(list(remap_results(x, pql=qcall))[0])
                        in removes,
                        rspdata.b64response(xx) in removes,
                    ]
                ):
                    newdata.append(x)
                else:
                    logger.debug(f"removing {x.get('metric')}", _ctx=_ctx, level=1)
                    span.add_event("removing", attributes=x.get("metric"))
                    span.set_status(StatusCode.ERROR)
        except Exception as err:
            logger.debug(f"Exception {err} parsing mdata.result", level=0, _ctx=_ctx)
            logger.debug(f"mdata = {mdata}", level=1, _ctx=_ctx)
            return data
        if len(mdata.get("result")) != len(newdata):
            logger.info(
                f"Tenant {tenant.name} roles {','.join(tenant.groups)} action {action} "
                + f"Original {len(mdata.get('result'))} Removed {len(removes)} New {len(newdata)}",
                level=0,
                _ctx=span,
            )
            span.set_status(StatusCode.ERROR)
        if all([len(removes) != 0, len(newdata) == 0]):
            for r in removes:
                logger.info(f"removed {x.get('metric')}", level=0, _ctx=span)
            span.set_status(StatusCode.ERROR)
            is_rejected = True

    if is_rejected == True:
        raise PermissionDenied()
    if isinstance(mdata, list):
        mdata = list(map(lambda x: x.get("name"), newdata))
    else:
        mdata["result"] = newdata
    return json.dumps({"status": "success", "data": mdata})


@get_tenant
@measure
async def handler(req, tenant=None):
    status = 200
    _ctx = get_tracecontext(headers=req.headers.copy())
    # try:
    if True:
        ### build proxy request ###
        reqparams = {
            "method": req.method,
            "url": f"{PROMURL}{str(req.path)}",
            "allow_redirects": True,
            "ssl": False,
        }
        _reqdata = await req.post()
        reqdata = _reqdata.copy()
        reqquery = req.query.copy()
        logger.debug(f"reqdata {reqdata}", _ctx=_ctx, level=1)
        logger.debug(f"reqquery {reqquery}", _ctx=_ctx, level=1)

        with tracer.start_as_current_span(
            "downstream request",
            attributes={
                "tenant": tenant.name,
                "source": req.headers.get("x-forwarded-for", "127.0.0.1"),
            },
        ) as span:
            _sctx = span.get_span_context()
            traceparent = get_traceparent(_ctx).header
            reqparams["headers"] = adjust_headers(req.headers.copy())
            span.set_attribute("method", reqparams["method"])
            span.set_attribute("url", reqparams["url"])
            span.set_status(StatusCode.OK)
            ### enforce labels extraction ###
            enforcing = []
            for name in req.headers.get("x-enforce-label", "cluster").split(","):
                try:
                    if getattr(tenant, name) != []:
                        enforcing.append(
                            f'{name}=~"(' + "|".join(getattr(tenant, name)) + ')"'
                        )
                except AttributeError:
                    pass
            if enforcing != []:
                logger.debug(f"enforcing = {enforcing}", _ctx=_ctx, level=3)
            ### filter request queries ###
            if not reqdata in (None, MultiDict()):
                try:
                    newdata = await parsequeries(
                        reqdata, tenant, "read", enforcing, _ctx
                    )
                    reqparams["data"] = newdata
                except PermissionDenied as perr:
                    headers = reqparams["headers"]
                    span.set_status(StatusCode.ERROR)
                    logger.error(
                        f"Permission Denied {tenant.name} action=read",
                        level=0,
                        _ctx=_sctx,
                    )
                    return web.Response(
                        body=perr.msg,
                        status=perr.code,
                        headers=dict(headers)
                        | {"traceparent": get_traceparent(span).header},
                    )
                except Exception as perr:
                    newdata = reqdata
                    reqparams["data"] = reqdata
                    logger.error(
                        f"Unhandled Exception for prasequeries {perr}",
                        level=0,
                        _ctx=_sctx,
                    )

            if not reqquery in (None, MultiDict()):
                try:
                    newdata = await parsequeries(
                        reqquery, tenant, "read", enforcing, _ctx
                    )
                    reqparams["params"] = newdata
                except PermissionDenied as perr:
                    headers = reqparams["headers"]
                    span.set_status(StatusCode.ERROR)
                    span.record_exception(perr)
                    logger.error(
                        f"Permission Denied {tenant.name} action=read",
                        level=0,
                        _ctx=_sctx,
                    )
                    return web.Response(
                        body=perr.msg,
                        headers=dict(headers)
                        | {"traceparent": get_traceparent(span).header},
                        status=perr.code,
                    )
                except Exception as perr:
                    newdata = reqquery
                    reqparams["params"] = reqquery
                    logger.error(
                        f"Unhandled Exception2 for prasequeries {perr}",
                        level=0,
                        _ctx=_sctx,
                    )
            # need to populate context for upstream
            _sctx = span.get_span_context()
            reqparams["headers"]["traceparent"] = get_traceparent(_sctx).header
            span.add_event(
                f"upstream request to {PROMURL}", attributes=params_to_trace(reqparams)
            )
            async with client.request(**reqparams) as resp:
                _ctx = get_tracecontext(headers=resp.headers.copy())
                logger.debug(f"downstream headers: {req.headers}", _ctx=_ctx, level=9)
                logger.debug(f"upstream request: {reqparams}", _ctx=_ctx, level=1)
                with tracer.start_as_current_span(
                    "upstream request",
                    attributes={
                        "tenant": tenant.name,
                        "action": "response",
                        "groups": ",".join(tenant.groups),
                        "upstream": reqparams["url"],
                        "method": reqparams["method"],
                    },
                ) as uspan:
                    body = await resp.read()
                    logger.debug(f"upstream response: {body}", _ctx=_ctx)
                    headers = resp.headers.copy()
                    if not tenant.has_group("Admin"):
                        try:
                            data = await parseresponse(
                                body, tenant, "response", reqparams, enforcing, _ctx
                            )
                        except PermissionDenied as perr:
                            logger.debug
                            logger.error(
                                f"Request {reqparams.get('data')} {reqparams.get('query')}",
                                level=0,
                                _ctx=_ctx,
                            )
                            span.set_status(StatusCode.ERROR)
                            uspan.set_status(StatusCode.ERROR)
                            uspan.set_status(StatusCode.ERROR)
                            uspan.record_exception(perr)
                            data = perr.msg
                            status = perr.code
                        uspan.set_status(StatusCode.OK)
                        if headers == None:
                            headers = resp.headers.copy()
                            headers["traceparent"] = get_traceparent(_ctx).header
                    else:
                        logger.debug(
                            f"not checking responses for {tenant.name} has group Admin"
                        )
                        data = body
                        status = 200

                    return web.Response(
                        status=status,
                        headers=dict(adjust_headers(headers))
                        | {"traceparent": get_traceparent(span).header},
                        body=data,
                    )
    try:
        pass
    except Exception as perr:
        logger.error(f"Exception {perr}", _ctx=_ctx)
        return web.Response(
            status=503,
            body=str(perr),
            headers={"traceparent": get_traceparent(_ctx).header},
        )


async def handler2(req):
    status = 200
    _ctx = get_tracecontext(headers=req.headers.copy())
    try:
        ### build proxy request ###
        reqparams = {
            "method": req.method,
            "url": f"{PROMURL}{str(req.path)}",
            "allow_redirects": True,
            "ssl": False,
        }
        _reqdata = await req.post()
        reqdata = _reqdata.copy()
        reqquery = req.query.copy()

        reqparams["headers"] = adjust_headers(req.headers.copy())
        ### filter request queries ###
        if not reqdata in (None, MultiDict()):
            try:
                reqparams["data"] = reqdata
            except PermissionDenied as perr:
                return web.Response(body=perr.msg, status=perr.code)

        if not reqquery in (None, MultiDict()):
            try:
                reqparams["params"] = reqquery
            except PermissionDenied as perr:
                return web.Response(body=perr.msg, status=perr.code)

        ### built proxy request ###

        async with client.request(**reqparams) as resp:
            body = await resp.read()
            try:
                data = body
            except PermissionDenied as perr:
                logger.error(
                    f"Request {reqparams.get('data')} {reqparams.get('query')}",
                    level=0,
                    _ctx=_ctx,
                )
                data = perr.msg
                status = perr.code
            headers = resp.headers.copy()
            return web.Response(
                status=status,
                headers=dict(adjust_headers(headers))
                | {"traceparent": get_traceparent(_ctx).header},
                body=data,
            )
    except Exception as perr:
        logger.error(f"Exception {perr}", _ctx=_ctx)
        return web.Response(
            status=503,
            body=str(perr),
            headers={"traceparent": get_traceparent(_ctx).header},
        )


async def app_factory():
    app = web.Application(middlewares=[opentelemetry])
    app.router.add_route("*", "/health", health)
    app.router.add_route("GET", "/metrics", metrics)
    app.router.add_route("*", "/api/v1/labels", handler2)
    app.router.add_route("*", "/api/v1/series", handler2)
    app.router.add_route("*", "/api/v1/metadata", handler2)
    app.router.add_route("*", "/api/v1/query", handler)
    app.router.add_route("*", "/api/v1/query_range", handler)
    app.router.add_route("*", "/api/v1/label/instance/values", handler)
    app.router.add_route("*", "/api/v1/label/cluster/values", handler)
    app.router.add_route("*", "/api/v1/label/namespace/values", handler)
    app.router.add_route("*", "/api/v1/label/name/values", handler)
    app.router.add_route("*", "/api/v1/label{tail:.*}", handler2)
    app.router.add_route("*", "/api/v1/parse_query", handler)
    app.router.add_route("*", "/api/v1/status/buildinfo", handler2)
    app.router.add_route("*", "/api/v1/query_exemplars", handler2)
    return app


if __name__ == "__main__":
    print(f"Running on {os.environ.get('POLICYAPI', 'http://localhost:3593')}")
    web.run_app(app_factory(), port=int(os.environ.get("PORT", 3985)))
