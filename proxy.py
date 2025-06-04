#!/usr/bin/python
import asyncio
import base64
import json
import logging
import os

import aiohttp
from aiohttp import client, web
from multidict import MultiDict, MultiDictProxy

from prompolicy.exceptions import *
from prompolicy.filters.cerbos import CerbosAPI
from prompolicy.tracing import *
from prompolicy.utils.generators import Metric2Cerbos, MetricsFactory
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
from prompolicy.utils.webrequests import adjust_headers, get_tenant, remap_results

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

PROMURL = os.environ.get("PROMAPI", "http://127.0.0.1:9091")
CERBOSAPI = os.environ.get("CERBOSAPI", "http://localhost:3593")

instrument()
tracer = trace.get_tracer("proxy")


@web.middleware
async def opentelemetry(request, handler):
    _ctx = get_tracecontext()

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
        logger.error(f"HealthState Prometheus not healthy {promerr}")
        return web.Response(
            status=503,
            body=str(promerr),
        )

    try:
        cerb = CerbosAPI(CERBOSAPI).is_healthy
        logger.error(f"CerbosAPI {cerb}")
    except Exception as cerberr:
        logger.error(f"HealthState Cerbos not healthy {cerberr}")
        return web.Response(
            status=503,
            body=str(cerberr),
        )
    return web.Response(status=200, body="OK")


async def parsequeries(data, tenant, action, _ctx):
    if data == None:
        return data
    try:
        metric = Metric2Cerbos(PromQL.parse(data.get("query")), tenant, action)
    except PromQLException:
        return data
    api = CerbosAPI(CERBOSAPI, tenant=tenant, action=action, tracecontext=_ctx)
    for perr in api.filter(metric):
        # logger.error(f"Permission Denied {tenant.name} {action}")
        raise PermissionDenied()
    return data


async def parseresponse(data, tenant, action, reqparams, _ctx):
    try:
        names = PromQL.parse(reqparams.get("data").get("query")).get_names()
    except Exception as perr:
        print(f"cannot parse reqparams query {perr}")
        print(f"{reqparams}")
        names = []
    if data == None:
        return data
    try:
        mdata = json.loads(data).get("data", False)
        if mdata == False:
            mdata = json.loads(data).get("result")
    except Exception:
        return data
    if isinstance(mdata, list):
        # do not check on labels all the time 2k+ queries
        return data
    else:
        try:
            rspdata = MetricsFactory.from_dict(
                remap_results(mdata.get("result"), names=names)
            )
        except AttributeError as err:
            print(f"AttributeError for metrics on result {err}")
            return data
        except Exception as err:
            print(f"Exception for metrics on result {err}")
            print(mdata)
    api = CerbosAPI(CERBOSAPI, tenant=tenant, action=action, tracecontext=_ctx)
    removes = list(api.paged_filter(rspdata, page_size=500, workers=10))
    newdata = []
    with tracer.start_as_current_span(
        "filtering",
        #        context=_ctx,
    ) as span:
        try:
            for x in mdata.get("result"):
                if x.get("metric", {}) == {}:
                    newdata.append(x)
                    continue
                try:
                    xx = x.get("metric")
                    xx["name"] = xx["__name__"]
                    del xx["__name__"]
                except Exception as xe:
                    xx = x.get("metric")
                if any(
                    [
                        rspdata.b64response(x.get("metric")) not in removes,
                        rspdata.b64response(xx) not in removes,
                    ]
                ):
                    newdata.append(x)
                else:
                    span.add_event("removing", attributes=x.get("metric"))
        except Exception as err:
            print(f"Exception {err} parsing mdata.result")
            print(f"mdata = {mdata}")
            # !!ToDo label list parsing and return here
            return data
    if len(mdata.get("result")) != len(newdata):
        print(
            f"Tenant {tenant.name} roles {','.join(tenant.groups)} action {action}"
            + f"Original {len(mdata.get('result'))} Removed {len(removes)} New {len(newdata)}"
        )
    if all([len(removes) != 0, len(newdata) == 0]):
        for r in removes:
            print(f"removed {x.get('metric')}")
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

        _ctx = get_tracecontext(headers=req.headers.copy())
        with tracer.start_as_current_span(
            "downstream request",
            #            context=_ctx,
        ) as span:
            _sctx = span.get_span_context()
            traceparent = f"00-{hex(_sctx.trace_id)[2:]}-{hex(_sctx.span_id)[2:]}-0{hex(_sctx.trace_flags)[2:]}"
            reqparams["headers"] = adjust_headers(req.headers.copy())
            span.set_attribute("method", reqparams["method"])
            span.set_attribute("url", reqparams["url"])
            span.set_status(StatusCode.OK)
            ### filter request queries ###
            if not reqdata in (None, MultiDict()):
                try:
                    newdata = await parsequeries(reqdata, tenant, "read", _ctx)
                    reqparams["data"] = reqdata
                except PermissionDenied as perr:
                    headers = reqparams["headers"]
                    TraceContextTextMapPropagator().inject(headers, _ctx)
                    logger.error(
                        f"Permission Denied {tenant.name} action=read", _ctx=_sctx
                    )
                    return web.Response(
                        body=perr.msg, status=perr.code, headers=headers
                    )

            if not reqquery in (None, MultiDict()):
                try:
                    newdata = await parsequeries(reqquery, tenant, "read", _ctx)
                    reqparams["params"] = reqquery
                except PermissionDenied as perr:
                    headers = reqparams["headers"]
                    span.set_status(StatusCode.ERROR)
                    span.record_exception(perr)
                    TraceContextTextMapPropagator().inject(headers, _ctx)
                    logger.error(
                        f"Permission Denied {tenant.name} action=action", _ctx=_sctx
                    )
                    return web.Response(
                        body=perr.msg, headers=headers, status=perr.code
                    )
            # need to populate context for upstream
            _sctx = span.get_span_context()
            reqparams["headers"][
                "traceparent"
            ] = f"00-{hex(_sctx.trace_id)[2:]}-{hex(_sctx.span_id)[2:]}-0{hex(_sctx.trace_flags)[2:]}"
            span.add_event(
                f"upstream request to {PROMURL}", attributes=params_to_trace(reqparams)
            )
            async with client.request(**reqparams) as resp:
                _ctx = get_tracecontext(headers=resp.headers.copy())
                with tracer.start_as_current_span(
                    "upstream request",
                    #       context=_ctx,
                ) as uspan:
                    body = await resp.read()
                    headers = resp.headers.copy()
                    try:
                        data = await parseresponse(
                            body, tenant, "response", reqparams, _ctx
                        )
                    except PermissionDenied as perr:
                        print(
                            f"Request {reqparams.get('data')} {reqparams.get('query')}"
                        )
                        span.set_status(StatusCode.ERROR)
                        uspan.set_status(StatusCode.ERROR)
                        uspan.set_status(StatusCode.ERROR)
                        uspan.record_exception(error)
                        data = perr.msg
                        status = perr.code
                    uspan.set_status(StatusCode.OK)
                    headers = TraceContextTextMapPropagator().inject(
                        dict(headers), _ctx
                    )
                    if headers == None:
                        headers = resp.headers.copy()
                        _ctx = uspan.get_span_context()
                        headers["traceparent"] = (
                            f"00-{hex(_ctx.trace_id)[2:]}-{hex(_ctx.span_id)[2:]}-0{hex(_ctx.trace_flags)[2:]}"
                        )

                    return web.Response(
                        status=status,
                        headers=adjust_headers(headers),
                        body=data,
                    )
    except Exception as perr:
        return web.Response(
            status=503,
            body=str(perr),
        )


async def handler2(req):
    status = 200
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
                print(f"Request {reqparams.get('data')} {reqparams.get('query')}")
                data = perr.msg
                status = perr.code
            headers = resp.headers.copy()
            return web.Response(
                status=status,
                headers=adjust_headers(headers),
                body=data,
            )
    except Exception as perr:
        return web.Response(status=503, body=str(perr))


async def app_factory():
    app = web.Application(middlewares=[opentelemetry])
    app.router.add_route("*", "/health", health)
    app.router.add_route("GET", "/metrics", metrics)
    app.router.add_route("*", "/api/v1/labels", handler2)
    app.router.add_route("*", "/api/v1/series", handler2)
    app.router.add_route("*", "/api/v1/metadata", handler2)
    app.router.add_route("*", "/api/v1/query", handler)
    app.router.add_route("*", "/api/v1/query_range", handler)
    app.router.add_route("*", "/api/v1/label{tail:.*}", handler2)
    app.router.add_route("*", "/api/v1/parse_query", handler)
    app.router.add_route("*", "/api/v1/status/buildinfo", handler2)
    app.router.add_route("*", "/api/v1/query_exemplars", handler2)
    # app.router.add_route("*", "/{tail:.*}", handler)
    return app


if __name__ == "__main__":
    print(f"Running on {os.environ.get('CERBOSAPI', 'http://localhost:3593')}")
    web.run_app(app_factory(), port=int(os.environ.get("PORT", 3985)))
