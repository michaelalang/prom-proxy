import promql_parser
from collections import namedtuple
import logging
from prompolicy.exceptions import PromQLException
from prompolicy.utils.logfilter import (
    FilteredLogger,
    LF_BASE,
    LF_WEB,
    LF_RESPONSES,
    LF_MODEL,
    LF_POLICY,
)
import os

MetricName = namedtuple("MetricName", ["name", "value", "regex"])
baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)
AUTH_HEADER = os.environ.get("AUTH_HEADER", "Authorization")


class FakeMatcher(object):
    def __init__(self):
        faker = namedtuple("FakeMatcher", ["matchers"])
        self.matchers = faker([])
        self.name = "fake"


def user_from_header(reqH):
    if reqH.get(AUTH_HEADER, False) is not False:
        user = reqH.get(AUTH_HEADER, ": anonymous").split(":")[-1].strip()
    else:
        user = os.environ.get("Authorization", "anonymous")
    return user


def _pqlbase(pql):
    try:
        pql.expr
        pqlbase = pql.expr
    except:
        try:
            pql.name
            pqlbase = pql
        except:
            try:
                pql.func.name
                pqlbase = pql
            except:
                pql.lhs
                pql.rhs
                pqlbase = pql
    return pqlbase


def find_labelset(matchers):
    mkeys = {}
    for m in matchers:
        try:
            regex = True if int(m.op) == 2 else False # 2 == MatchOp.Re, 0 == Match.Equal
        except Exception as regerr:
            regex = False
        mkeys[m.name] = MetricName(m.name, m.value, regex)
    return mkeys


def get_labelset(additional, mkeys):
    regexed = list(filter(lambda x: mkeys[x].regex, mkeys))
    if additional.get("name") in list(filter(lambda x: mkeys[x].name, regexed)):
        regex = True
    else:
        regex = False
    additional.update(
        {
            "instance": mkeys.get("instance", MetricName("", "", False)).value,
            "job": mkeys.get("job", MetricName("", "", False)).value,
            "regex": regex,
        }
    )
    return additional


def getmatchers(lhsandrhs):
    for m in lhsandrhs:
        for mm in m:
            yield mm


def get_matchers_deep(pqlbase, k):
    matcher = pqlbase
    for _ in range(10):
        logger.debug(f"iterating get_matchers {type(matcher)}", LF_RESPONSES)
        try:
            if isinstance(matcher, promql_parser.BinaryExpr):
                matcher = getattr(matcher, k)
                continue
            elif isinstance(matcher, promql_parser.VectorSelector):
                break
            elif isinstance(matcher, promql_parser.AggregateExpr):
                matcher = _pqlbase(matcher)
                continue
            elif isinstance(matcher, promql_parser.NumberLiteral):
                matcher = FakeMatcher()
                break
            elif isinstance(matcher, promql_parser.ParenExpr):
                matcher = _pqlbase(_pqlbase(matcher))
                return get_matchers_deep(matcher, k)
            elif isinstance(matcher, promql_parser.Call):
                for arg in matcher.args:
                    # logger.error(f"args from Call {type(arg)}")
                    if isinstance(arg, promql_parser.MatrixSelector):
                        return arg.vector_selector
                    elif isinstance(arg, promql_parser.VectorSelector):
                        return arg
                    elif isinstance(arg, promql_parser.ParenExpr):
                        matcher = _pqlbase(_pqlbase(arg))
                        return get_matchers_deep(matcher, k)
                    elif isinstance(arg, promql_parser.AggregateExpr):
                        matcher = _pqlbase(_pqlbase(arg))
                        return get_matchers_deep(matcher, k)
                break
        except Exception as e:
            logger.error(f"EXCEPTION get_matchers_deep {e}", LF_BASE)
            break
    return matcher


def vector_to_policy(pql):
    # requests_total{tenant="namespace1", method="GET"}

    pqlbase = _pqlbase(pql)
    matchers = []
    matchers.extend(list(map(lambda x: x, pqlbase.matchers.matchers)))
    mkeys = find_labelset(matchers)
    pcheck = [
        {
            "metric": get_labelset(
                {
                    "name": pqlbase.name,
                },
                mkeys,
            )
        }
    ]
    pcheck.extend(
        list(
            map(
                lambda x: {
                    "label": get_labelset(
                        {
                            "name": x.name,
                        },
                        mkeys,
                    )
                },
                matchers,
            )
        )
    )
    return pcheck, matchers


def binary_connect(pql, reqH):
    pqlbase = _pqlbase(pql)

    # for authentication we receive 1+1
    try:
        if all([pqlbase.lhs.val == 1.0, pqlbase.rhs.val == 1.0, str(pql.op) == "+"]):
            return user_from_header(reqH)
    except:
        # not a 1+1 BinaryExpr
        raise PromQLException("invalid BinaryExpr")


def binary_to_policy(pql):
    # arithmetic functions like 1+1

    pqlbase = _pqlbase(pql)

    matchers = []

    try:
        matchers.extend(
            list(
                map(
                    lambda x: x,
                    getmatchers(
                        [
                            get_matchers_deep(pqlbase, "lhs").matchers.matchers,
                            get_matchers_deep(pqlbase, "rhs").matchers.matchers,
                        ]
                    ),
                )
            )
        )
    except Exception as e:
        logger.debug(f"BINARY_TO_POLICY Exception {e}", LF_MODEL)
        logger.debug(f"BINARY_TO_POLOCY pql: {pql}", LF_MODEL)
        return [], []

    mkeys = find_labelset(matchers)
    pcheck = [
        {"function": {"name": str(pqlbase.op)}},
        {
            "metric": get_labelset(
                {
                    "name": get_matchers_deep(pqlbase, "lhs").name,
                },
                mkeys,
            )
        },
        {
            "metrics": get_labelset(
                {
                    "name": get_matchers_deep(pqlbase, "rhs").name,
                },
                mkeys,
            )
        },
    ]
    pcheck.extend(
        list(
            map(
                lambda x: {
                    "label": get_labelset(
                        {
                            "name": x.name,
                        },
                        mkeys,
                    )
                },
                matchers,
            )
        )
    )
    return pcheck, matchers


def parent_to_policy(pql):
    pqlbase = _pqlbase(pql)

    matchers = []
    matchers.extend(
        list(
            map(
                lambda x: x,
                getmatchers(
                    [
                        get_matchers_deep(pqlbase, "lhs").matchers.matchers,
                        get_matchers_deep(pqlbase, "rhs").matchers.matchers,
                    ]
                ),
            )
        )
    )
    mkeys = find_labelset(matchers)
    pcheck = [
        {"function": {"name": str(pql.expr.op)}},
        {
            "metric": get_labelset(
                {
                    "name": pqlbase.lhs.name,
                },
                mkeys,
            )
        },
        {
            "metrics": get_labelset(
                {
                    "name": pqlbase.rhs.name,
                },
                mkeys,
            )
        },
    ]

    pcheck.extend(
        list(
            map(
                lambda x: {
                    "label": get_labelset(
                        {
                            "name": x.name,
                        },
                        mkeys,
                    )
                },
                matchers,
            )
        )
    )
    return pcheck, matchers


def aggr_to_policy(pql):
    # 'sum(irate(node_cpu_seconds_total{instance="x",job="node", mode="system"}[1m0s])) /
    # j scalar(count(count(node_cpu_seconds_total{instance="x",job="node"}) by (cpu)))'
    pqlbase = _pqlbase(pql)
    logger.debug(f"promql_parser.AggregateExpr {str(pqlbase)}", LF_MODEL)
    matchers = []
    matchers.extend(
        list(
            map(
                lambda x: x,
                list(
                    map(
                        lambda y: y.vector_selector.matchers.matchers,
                        pqlbase.args,
                    )
                )[0],
            )
        )
    )
    matchers.extend(
        map(
            lambda x: MetricName(x.vector_selector.name, x.vector_selector.name),
            pqlbase.args,
        )
    )
    mkeys = find_labelset(matchers)
    pcheck = [
        {
            "function": get_labelset(
                {
                    "name": str(pqlbase.op),
                    "return_type": str(pqlbase.func.return_type).split(".")[-1],
                },
                mkeys,
            )
        },
        {
            "function": get_labelset(
                {
                    "name": pqlbase.func.name,
                    "arg_types": list(
                        map(
                            lambda x: str(x).split(".")[-1],
                            pqlbase.func.arg_types,
                        )
                    )[0],
                    "variadic": bool(pqlbase.func.variadic),
                    "return_type": str(pqlbase.func.return_type).split(".")[-1],
                },
                mkeys,
            )
        },
    ]

    pcheck.extend(
        list(
            map(
                lambda x: {
                    "label": get_labelset(
                        {
                            "name": x.name,
                        },
                        mkeys,
                    )
                },
                matchers,
            )
        )
    )
    return pcheck, matchers


def call_to_policy(pql):
    pqlbase = _pqlbase(pql)
    pqlbase.func.name
    matchers = []
    matchers.extend(
        list(
            map(
                lambda x: x,
                list(
                    map(
                        lambda y: y.vector_selector.matchers.matchers,
                        pqlbase.args,
                    )
                )[0],
            )
        )
    )
    matchers.extend(
        map(
            lambda x: MetricName(x.vector_selector.name, x.vector_selector.name, False),
            pqlbase.args,
        )
    )
    mkeys = find_labelset(matchers)
    pcheck = [
        {
            "function": get_labelset(
                {
                    "name": pqlbase.func.name,
                    "arg_types": list(
                        map(
                            lambda x: str(x).split(".")[-1],
                            pqlbase.func.arg_types,
                        )
                    )[0],
                    "variadic": bool(pqlbase.func.variadic),
                    "return_type": str(pqlbase.func.return_type).split(".")[-1],
                },
                mkeys,
            )
        }
    ]
    pcheck.extend(
        list(
            map(
                lambda x: {
                    "label": get_labelset(
                        {
                            "name": x.name,
                        },
                        mkeys,
                    )
                },
                matchers,
            )
        )
    )
    return pcheck, matchers


def expr_to_policy(pql):
    # are we a expression metric query
    pqlbase = _pqlbase(pql)
    matchers = pqlbase.matchers.matchers
    matchers = [MetricName(pql.name, pql.name, False)]
    matchers.extend(list(map(lambda x: x, pqlbase.matchers.matchers)))
    mkeys = find_labelset(matchers)
    pcheck = list(
        map(
            lambda x: {
                "label": get_labelset(
                    {
                        "name": x.name,
                    },
                    mkeys,
                )
            },
            matchers,
        )
    )
    return pcheck, matchers
