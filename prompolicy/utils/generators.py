import base64
import json
import logging
import os
import urllib.parse
import uuid
from collections import defaultdict
from copy import deepcopy

import jwt
from cerbos.engine.v1 import engine_pb2
from cerbos.sdk.model import Principal, Resource, ResourceAction, ResourceList
from google.protobuf.struct_pb2 import Value, ListValue

from prompolicy.promstats import POLICY_ITEMS
from prompolicy.utils.logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)

baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)


CERBOSAPI = urllib.parse.urlparse(os.environ.get("CERBOSAPI", "http://localhost:3593"))


def adjust_headers(headers):
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


def b64encode(content):
    ctx = deepcopy(content)
    if isinstance(ctx, dict):
        for k in ("values", "value"):
            if ctx.get(k, False) is not False:
                del ctx[k]
    try:
        return base64.b64encode(json.dumps(ctx).encode("utf8")).decode("utf8")
    except:
        try:
            ctx = json.loads(ctx)
            return base64.b64encode(json.dumps(ctx).encode("utf8")).decode("utf8")
        except:
            logger.error(f"POLICY not jsonable {ctx}", LF_BASE)
            return str(uuid.uuid4())


def generate_functions(functions, tenant, action):
    if functions == None:
        return

    def function_to_grpc(promfunc, tenant, action):
        attrs = {
            "public": Value(bool_value=False),
            "owner": Value(string_value="node"),  # Value(string_value=tenant.id),
            "kind": Value(string_value="function"),
        }
        for k in promfunc:
            kk = "name" if k == "__name__" else k
            if isinstance(promfunc[k], bool):
                attrs[kk] = Value(bool_value=promfunc[k])
            elif isinstance(promfunc[k], str):
                attrs[kk] = Value(string_value=promfunc[k])
            elif isinstance(promfunc[k], list):
                attrs[kk] = Value(string_value=promfunc[k][0])
            else:
                attrs[kk] = Value(string_value=str(promfunc[k]))
        logger.debug(f"generate_functions {attrs}", LF_MODEL)
        POLICY_ITEMS.labels(tenant.id, "metric", action).inc()
        return attrs

    def function_to_dict(promfunc, tenant, action):
        attrs = {
            "public": False,
            "owner": tenant.id,
            "kind": "function",
        }
        for k in promfunc:
            attrs[k] = promfunc[k]
        logger.debug(f"generate_functions {attrs}", LF_MODEL)
        POLICY_ITEMS.labels(tenant.id, "metric", action).inc()
        return attrs

    for promfunc in functions:
        if CERBOSAPI.scheme == "grpc":
            yield engine_pb2.Resource(
                id=f"{b64encode(promfunc)}",
                kind="function",
                attr=function_to_grpc(promfunc.get("function"), tenant, action),
            )
        else:
            yield ResourceAction(
                Resource(
                    f"{b64encode(promfunc)}",
                    "function",
                    attr=function_to_dict(promfunc.get("function"), tenant, action),
                ),
                actions=["read"],
            )


def generate_metrics(metrics, tenant, action):
    if metrics == None:
        return
    logger.debug(f"GENERATE_METRICS data {metrics}", LF_MODEL)

    def metric_to_resource(data):
        return {"metric": {"name": data}}

    def metric_to_grpc(metric, tenant, action):
        logger.debug(f"METRIC_TO_GRPC debug {metric}", LF_MODEL)
        attrs = {
            "public": Value(bool_value=False),
            "owner": Value(string_value="node"),  # Value(string_value=tenant.id),
            "kind": Value(string_value="metric"),
        }
        for k in metric:
            kk = "name" if k == "__name__" else k
            if isinstance(metric[k], bool):
                attrs[kk] = Value(bool_value=metric[k])
            else:
                attrs[kk] = Value(string_value=str(metric[k]))
        logger.debug(f"metric_to_grpc: {attrs}", LF_MODEL)
        POLICY_ITEMS.labels(tenant.id, "metric", action).inc()
        return attrs

    def metric_to_dict(metric, tenant):
        attrs = {
            "public": False,
            "owner": "node",  # tenant.id,
            "kind": "metric",
        }
        for k in metric:
            kk = "name" if k == "__name__" else k
            if isinstance(metric[k], bool):
                attrs[kk] = Value(bool_value=metric[k])
            else:
                attrs[kk] = Value(string_value=str(metric[k]))
        POLICY_ITEMS.labels(tenant.id, "metric", action).inc()
        logger.debug(f"GENERATE_METRIC metric_to_grpc: {attrs}", LF_MODEL)
        return attrs

    seen = defaultdict(bool)
    for metric in metrics:
        if metric in ("value", "values", "tenant"):
            continue
        if not isinstance(metric, dict):
            if str(metric) == "metric":
                continue
            metric = metric_to_resource(metric)
        if metric.get("name") in ("tenant",):
            continue
        if seen[metric.get("name", False)]:
            continue
        seen[metric.get("name")] = True
        if all(
            [
                # {'metric': {}, 'values': [...]
                metric.get("metric", {}) == {},
                any(
                    [
                        len(metric.get("values", [])) > 0,
                        len(metric.get("value", [])) > 0,
                    ]
                ),
            ]
        ):
            # happens when for example the query is sum(up{})
            logger.debug(f"Ignoring metric due to being empty {metric}", LF_RESPONSES)
            continue
        if CERBOSAPI.scheme == "grpc":
            yield engine_pb2.Resource(
                id=f"{b64encode(metric)}",
                kind="metric",
                attr=metric_to_grpc(
                    metric.get("metric"),
                    tenant,
                    action,
                ),
            )
        else:
            yield ResourceAction(
                Resource(
                    f"{b64encode(metric)}",
                    "metric",
                    attr=metric_to_dict(metric.get("metric"), tenant, action),
                ),
                actions=["read"],
            )


def generate_labels(labels, tenant, action):
    if labels == None:
        return
    logger.debug(f"GENERATE_LABELS data {labels}", LF_MODEL)

    def label_to_resource(data):
        return {"metric": {"name": data}}

    def label_to_grpc(label, tenant, action):
        logger.debug(f"LABEL_TO_GRPC debug {label}", LF_MODEL)
        attrs = {
            "public": Value(bool_value=False),
            "owner": Value(string_value="node"),  # Value(string_value=tenant.id),
            "kind": Value(string_value="label"),
        }
        for k in label:
            kk = "name" if k == "__name__" else k
            if isinstance(label[k], bool):
                attrs[kk] = Value(bool_value=label[k])
            else:
                attrs[kk] = Value(string_value=str(label[k]))
        logger.debug(f"label_to_grpc: {attrs}", LF_MODEL)
        POLICY_ITEMS.labels(tenant.id, "label", action).inc()
        return attrs

    def label_to_dict(label, tenant):
        attrs = {
            "public": False,
            "owner": "node",  # tenant.id,
            "kind": "label",
        }
        for k in label:
            kk = "name" if k == "__name__" else k
            if isinstance(label[k], bool):
                attrs[kk] = Value(bool_value=label[k])
            else:
                attrs[kk] = Value(string_value=str(label[k]))
        POLICY_ITEMS.labels(tenant.id, "label", action).inc()
        logger.debug(f"GENERATE_LABEL label_to_grpc: {attrs}", LF_MODEL)
        return attrs

    seen = defaultdict(bool)
    for label in labels:
        if label in ("value", "values"):
            continue
        if not isinstance(label, dict):
            if str(label) == "label":
                continue
            label = label_to_resource(label)
        if label.get("label", {}).get("name") in ("tenant",):
            continue
        if seen[label.get("name", False)]:
            continue
        seen[label.get("name")] = True
        if all(
            [
                # {'label': {}, 'values': [...]
                label.get("label", {}) == {},
                any(
                    [
                        len(label.get("values", [])) > 0,
                        len(label.get("value", [])) > 0,
                    ]
                ),
            ]
        ):
            # happens when for example the query is sum(up{})
            logger.debug(f"Ignoring label due to being empty {label}", LF_RESPONSES)
            continue
        if CERBOSAPI.scheme == "grpc":
            yield engine_pb2.Resource(
                id=f"{b64encode(label)}",
                kind="label",
                attr=label_to_grpc(
                    label.get("label"),
                    tenant,
                    action,
                ),
            )
        else:
            yield ResourceAction(
                Resource(
                    f"{b64encode(label)}",
                    "label",
                    attr=label_to_dict(label.get("label"), tenant, action),
                ),
                actions=["read"],
            )


def get_principal(name):
    rolemappings = {}
    try:
        token = jwt.JWT().decode(name.split()[-1], do_verify=False)
    except Exception as jwterr:
        try:
            token = jwt.JWT().decode(name, do_verify=False)
        except Exception as jwterr:
            logger.debug(f"cannot decode JWT from {name}")
            token = {}
    # different types of JWTs so check if we can have a username
    # TODO: make ordering and selected JWT field configurable
    name = (
        token.get("preferred_username")
        if token.get("preferred_username", False) is not False
        else (
            token.get("username")
            if token.get("username", False) is not False
            else token.get("email")
        )
    )

    groups = (
        token.get("groups")
        if token.get("groups", False) is not False
        else (
            token.get("resource_access", {}).get("account", {}).get("roles")
            if token.get("resource_access", {}).get("account", {}).get("roles", False)
            is not False
            else ["user"]
        )
    )

    if token.get("kubernetes.io/serviceaccount/namespace", False) is not False:
        groups.append(token.get("kubernetes.io/serviceaccount/namespace"))

    rolemappings = {name: groups}

    def roles_to_listvalue(roles):
        r = ListValue()
        map(lambda x: r.append(x), set(roles))
        return r

    if CERBOSAPI.scheme == "grpc":

        def map_attrs(attrs):
            newattrs = {}
            for attr in attrs:
                newattrs[attr] = (
                    Value(string_value=attrs[attr])
                    if isinstance(attrs[attr], str)
                    else attrs[attr]
                )
            return newattrs

        principal = engine_pb2.Principal(
            id=name,
            roles=list(set(rolemappings.get(name, ["user"]))),
            policy_version="20210210",
            attr={},
        )
        logger.error(f"!!! Principal with roles {principal}")
    else:
        principal = Principal(
            name,
            roles={
                "user",
            },
            attr={},  # "roles": set(rolemappings.get(name, ["user"]))},
        )
    return principal


def remap_results(data, values=False):
    try:
        newdata = {"metric": {}}
        for k in data.get("metric"):
            if k == "__name__":
                newdata["metric"]["name"] = data["metric"][k]
            else:
                newdata["metric"][k] = data["metric"][k]
        if values:
            try:
                newdata["values"] = data["values"]
            except KeyError as kerr:
                try:
                    newdata["value"] = data["value"]
                except KeyError as kerr:
                    logger.error(f"remap_results data keys {data.keys()}")
                    raise KeyError(kerr)
        return newdata
    except AttributeError:
        return data
