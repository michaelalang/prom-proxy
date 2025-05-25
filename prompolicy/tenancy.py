import traceback
from prompolicy.utils.logfilter import (
    FilteredLogger,
    LF_BASE,
    LF_WEB,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
)
from prompolicy.exceptions import (
    PermissionDenied,
    PromQLException,
    Learning,
    CerbosGRPCDown,
)
from prompolicy.utils.generators import (
    generate_functions,
    generate_metrics,
    generate_labels,
    get_principal,
    b64encode,
)
from prompolicy.utils.prom_to_policy import (
    vector_to_policy,
    binary_connect,
    binary_to_policy,
    parent_to_policy,
    aggr_to_policy,
    call_to_policy,
    expr_to_policy,
    user_from_header,
)
from grpc._channel import _InactiveRpcError
from prompolicy.promstats import VIOLATIONS_TOTAL, GRPC_CALLS_LATENCY, GRPC_CALLS_TOTAL
from prompolicy.utils.prom_to_policy import user_from_header
from collections import namedtuple
import promql_parser
import os
from concurrent.futures import ThreadPoolExecutor, wait
from multidict import MultiDictProxy, MultiDict
import logging
import urllib.parse
import base64
from time import time

from cerbos.sdk.grpc.client import CerbosClient as CerbosClientGRPC
from cerbos.engine.v1 import engine_pb2
from cerbos.request.v1 import request_pb2
from cerbos.sdk.grpc.utils import is_allowed
from cerbos.sdk.model import Principal, ResourceList

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

PAGESIZE = int(os.environ.get("PAGESIZE", 500))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 10))
TENANT_FILTER = "tenant"
CERBOSAPI = urllib.parse.urlparse(os.environ.get("CERBOSAPI", "http://localhost:3593"))
baseUrl = os.environ.get("PROMAPI", "http://127.0.0.1:9091")
LEARNING = bool(int(os.environ.get("LEARNING", False)))
REPLACE_LABELS = bool(int(os.environ.get("REPLACE_LABELS", True)))
AUTH_HEADER = os.environ.get("AUTH_HEADER", "Authorization")


def replace_tenant_labels(tenant, query, data):
    logger.error(f"replace received data {data} {query} {tenant.id}", LF_MODEL)
    if REPLACE_LABELS:
        # possible scenarios:
        # metric{tenant="some", ...}
        # metric{..., tenant="some", ...}
        # metric{..., tenant="some"}
        if query.get("query", None) is not None:
            query["query"] = (
                query.get("query")
                .replace("{" + TENANT_FILTER + f'="{tenant.id}", ', "{")
                .replace(f', {TENANT_FILTER}="{tenant.id}"', "")
                .replace(f',{TENANT_FILTER}="{tenant.id}"', "")
                .replace(f'{TENANT_FILTER}="{tenant.id}"', "")
                .replace(f', {TENANT_FILTER}="{tenant.id}"' + "}", "}")
                .replace(f',{TENANT_FILTER}="{tenant.id}"' + "}", "}")
                .replace(",,", ",")
                .replace(", ,", ",")
            )
            logger.error(f"replaced query {query.get('query')}", LF_MODEL)
        elif data.get("query") is not None:
            data = (
                data["query"]
                .replace("{" + TENANT_FILTER + f'="{tenant.id}", ', "{")
                .replace(f', {TENANT_FILTER}="{tenant.id}"', "")
                .replace(f',{TENANT_FILTER}="{tenant.id}"', "")
                .replace(f'{TENANT_FILTER}="{tenant.id}"', "")
                .replace(f', {TENANT_FILTER}="{tenant.id}"' + "}", "}")
                .replace(f',{TENANT_FILTER}="{tenant.id}"' + "}", "}")
                .replace(",,", ",")
                .replace(", ,", ",")
            )
            logger.error(f"replaced data {data}", LF_MODEL)
    return query, data


def deduplicate(pcheck):
    ncheck = []
    seen = []
    try:
        for p in pcheck:
            if b64encode(str(p)) in seen:
                continue
            ncheck.append(p)
        return ncheck
    except:
        return pcheck


def require_tenancy(data, req):
    query = data.copy()
    reqH = req.headers.copy()
    pcheck = []

    logger.info(f"data received {query}", LF_RESPONSES)
    # ignore queries of "start=xxx end=xxxx"
    if any(
        [
            all(
                [
                    len(query) == 2,
                    query.get("start", False) is not False,
                    query.get("end", False) is not False,
                ]
            ),
            query == MultiDict(),
        ]
    ):
        user = user_from_header(reqH)
        tenant = get_principal(user)
        return (
            tenant,
            query,
        )
    try:
        try:
            pqlquery = query.get("query", False)
            if pqlquery is False:
                raise PromQLException("unparse able")
        except PromQLException as e:
            try:
                pqlquery = query.get("match[]")
            except Exception as e:
                try:
                    query = req.query.copy()
                    if query == MultiDict():
                        raise PromQLException(str(e))
                except PromQLException as e:
                    logger.error(f"PQL Exception {e}", LF_RESPONSES)
                    logger.debug(f"UNTRACKED {data}", LF_RESPONSES)
                tenant = get_principal(user_from_header(reqH))
                return (tenant, query)
        try:
            pqlquery = query.get("query")
        except Exception as pqerr:
            logger.debug(f"PQLQUERY {query.get('query')}", LF_MODEL)
            logger.debug(f"PQLQUERY Exception {e}", LF_MODEL)
        if pqlquery == None:
            try:
                pqlquery = query.get("match[]")
            except Exception as e:
                logger.debug(f"UNTRACKED {data}", LF_RESPONSES)
                raise PromQLException(f"untracked {data}")
        # tenant = get_principal(user_from_header(reqH))
        # return (tenant, query)
        try:
            pql = promql_parser.parse(pqlquery)
            logger.debug(pql, LF_RESPONSES)
        except ValueError:
            # somehow promql doesnt support variables like $__rate_interval
            try:
                pql = promql_parser.parse(pqlquery.replace("$__rate_interval", "5m"))
            except Exception as pqlerr:
                logger.error(f"PQLErrpr {pqlquery}", LF_BASE)
                raise PromQLException(f"unparse able PromQL query {pqlerr}")
        if isinstance(pql, promql_parser.BinaryExpr):
            try:
                user = binary_connect(pql, reqH)
                tenant = get_principal(user)
                return (
                    tenant,
                    query,
                )
            except PromQLException:
                pass
            pcheck, matchers = binary_to_policy(pql)
        elif isinstance(pql, promql_parser.VectorSelector):
            pcheck, matchers = vector_to_policy(pql)
        elif isinstance(pql, promql_parser.ParenExpr):
            pcheck, matchers = parent_to_policy(pql)
        elif isinstance(pql, promql_parser.AggregateExpr):
            pcheck, matchers = aggr_to_policy(pql)
        elif isinstance(pql, promql_parser.Call):
            pcheck, matchers = call_to_policy(pql)
        else:
            pcheck, matchers = expr_to_policy(pql)
        pcheck = deduplicate(pcheck)
        logger.debug(f"PCHECK {pcheck}", LF_RESPONSES)
        try:
            try:
                label = list(filter(lambda x: x.name == TENANT_FILTER, matchers))[0]
                logger.debug(f"PQL Tenant = {label}", LF_MODEL)
                tenant = get_principal(label.value)
            except IndexError:
                # we need the tenant label
                # doesn't make sense to have this in Learning as there's no tenant label
                raise PermissionDenied()
            except AttributeError:
                logger.debug(
                    f"1 Label {list(filter(lambda x: x.name == TENANT_FILTER, matchers))}",
                    LF_MODEL,
                )
                try:
                    label = list(filter(lambda x: str(x) == TENANT_FILTER, matchers))[0]
                    tenant = get_principal(label)
                except IndexError:
                    logger.debug(
                        f"2 Label before raised exception Checking data {data.get('tenant', False)}",
                        LF_MODEL,
                    )
                    if data.get("tenant", False) is not False:
                        tenant = get_principal(data.get("tenant"))
                    else:
                        tenant = get_principal("anonymous")
        except Exception as te:
            logger.debug(f"2 Exception {te}", LF_RESPONSES)
            if reqH.get(AUTH_HEADER, False) is not False:
                user = reqH.get(AUTH_HEADER, ": anonymous").split(":")[-1].strip()
            else:
                user = os.environ.get("Authorization", "anonymous")
            tenant = get_principal(user)
            logger.debug(f"2 Tenant {tenant}", LF_MODEL)
        logger.error(f"PCHECK {pcheck}", LF_RESPONSES)
        check = list(
            page_policy_resources(
                pcheck,
                tenant,
                action="read",
            )
        )
        if check != []:
            if not LEARNING:
                raise PermissionDenied()
    except _InactiveRpcError as grpcerr:
        logger.error(f"GRPC unavailable", LF_BASE)
        raise CerbosGRPCDown(str(grpcerr))
    except Learning as permerr:
        raise permerr
    except PermissionDenied as permerr:
        raise permerr
    except PromQLException as promerr:
        traceback.print_exception(promerr)
        raise PromQLException(str(promerr))
    except Exception as te3:
        traceback.print_exception(te3)
        if "expected type" in str(te3):
            raise PromQLException(str(te3))
        user = user_from_header(reqH)
        tenant = get_principal(user)
        logger.debug(f"3 Exception tenant {tenant}", LF_MODEL)
        if not all([query.get("start", False), query.get("end", False)]):
            res = list(
                page_policy_resources(
                    [
                        # {"metric": {}},
                        # {"function": {"name": ""}},
                    ],
                    tenant,
                    action="read",
                )
            )
            logger.debug(f"3 Exception res {res}", LF_RESPONSES)
            if res != []:
                logger.error(f"Tenant {tenant.id} not allowed to query")
                if not LEARNING:
                    raise PermissionDenied()
        if not LEARNING:
            raise PermissionDenied()
    logger.info(f"data parsed {query}", LF_RESPONSES)
    if all(
        [
            MultiDictProxy(MultiDict(query)) == MultiDictProxy(MultiDict()),
            data == MultiDictProxy(MultiDict()),
        ]
    ):
        logger.info(f"Tenant {tenant.id} not allowed to query all data empty")
        if not LEARNING:
            raise PermissionDenied()
    # query, data = replace_tenant_labels(tenant, query, data)
    return (
        tenant,
        MultiDictProxy(MultiDict(query)) if query is not None else data,
    )


def page_policy_resources(jbody=[], tenant=None, action="read"):
    # bad to hardcode but no other idea right now
    logger.debug(
        f"page_policy_resources called with tenant {tenant} roles action {action}",
        LF_POLICY,
    )
    resource_list = ResourceList(resources=[])
    if not action == "response":
        rec_f = filter(lambda x: x.get("function", False), jbody)
        rec_e = filter(lambda x: x.get("metric", False), jbody)
        rec_l = filter(lambda x: x.get("label", False), jbody)
    else:
        rec_e = jbody
    try:
        resource_list.resources.extend(
            generate_functions(deduplicate(rec_f), tenant, action)
        )
    except:
        pass
    resource_list.resources.extend(generate_metrics(deduplicate(rec_e), tenant, action))
    try:
        resource_list.resources.extend(
            generate_labels(deduplicate(rec_l), tenant, action)
        )
    except:
        pass
    size = len(resource_list.resources)
    if size == 0:
        logger.debug(f"resource_list size {size} {resource_list.resources}", LF_POLICY)
        return None
    page = 0
    if not isinstance(tenant, (engine_pb2.Principal, Principal)):
        tenant = get_principal(str(tenant))

    def policy_verify(page, pend, resource_list, action):
        starttime = time()
        if CERBOSAPI.scheme == "grpc":
            with CerbosClientGRPC(CERBOSAPI.netloc, tls_verify=False) as cerb:
                GRPC_CALLS_TOTAL.labels(tenant.id, action).inc()
                resp = cerb.check_resources(
                    principal=tenant,
                    resources=list(
                        map(
                            lambda x: request_pb2.CheckResourcesRequest.ResourceEntry(
                                actions=[action], resource=x
                            ),
                            resource_list.resources[page:pend],
                        )
                    ),
                )
                logger.info(
                    f"CERBOS call_id: tenant {tenant.id} {resp.cerbos_call_id} {action}",
                    LF_BASE,
                )
                avoid_log_flood = False
                for r in list(
                    map(
                        lambda y: y,
                        list(filter(lambda x: not is_allowed(x, action), resp.results)),
                    )
                ):
                    try:
                        if not avoid_log_flood:
                            logger.error(
                                f"VIOLATION [{action}] {tenant.id} {base64.b64decode(r.resource.id).decode('utf8')}",
                                LF_BASE,
                            )
                            avoid_log_flood = True
                    except Exception as e:
                        logger.debug(f"VIOLATION r-{r}- t-{tenant}- e-{e}-", LF_POLICY)
                    VIOLATIONS_TOTAL.labels(tenant.id, action, r.resource.kind).inc()
                    yield r.resource.id
        else:
            with CerbosClient(host=CERBOSAPI.geturl()) as cerb:
                resp = cerb.check_resources(
                    principal=tenant,
                    resources=ResourceList(
                        resources=resource_list.resources[page:pend]
                    ),
                )
                for r in list(
                    map(
                        lambda y: y.resource.id,
                        list(
                            filter(lambda x: not x.is_allowed([action]), resp.results)
                        ),
                    )
                ):
                    try:
                        if not avoid_log_flood:
                            logger.error(
                                f"VIOLATION [{action}] {tenant.id} {base64.b64decode(r.resource.id).decode('utf8')}",
                                LF_BASE,
                            )
                            avoid_log_flood = True
                    except Exception as e:
                        logger.debug(f"VIOLATION r-{r}- t-{tenant}- e-{e}-", LF_POLICY)
                    logger.debug(f"Resource {r.resource.id}", LF_RESPONSES)
                    VIOLATIONS_TOTAL.labels(tenant.id, action, r.resource.kind).inc()
                    yield r
        stoptime = time()
        GRPC_CALLS_LATENCY.labels(
            tenant.id, len(resource_list.resources[page:pend])
        ).observe(
            stoptime - starttime  # , {"trace_id": traceid}
        )

    threads = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as tpe:
        while True:
            pend = page + PAGESIZE if page + PAGESIZE <= size else size
            logger.debug(
                f"threading off for {page} -> {pend} action {action}", LF_POLICY
            )
            threads.append(tpe.submit(policy_verify, page, pend, resource_list, action))
            page = page + PAGESIZE
            if page > size:
                break
    wait(threads)

    for thread in threads:
        for res in thread.result():
            logger.debug(f"RESULTS {res}", LF_RESPONSES)
            yield res
