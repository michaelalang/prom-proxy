import base64
import logging
import os
import string
import sys
from functools import wraps
from typing import ByteString, Dict, Iterable, List, Self, Tuple

import promql_parser

from ..exceptions import *
from .logfilter import (
    LF_BASE,
    LF_MODEL,
    LF_POLICY,
    LF_RESPONSES,
    LF_WEB,
    FilteredLogger,
)

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
baselevel = logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
logger = FilteredLogger(__name__, baselevel=baselevel)

PromQLFunctions = (
    # FROM https://prometheus.io/docs/prometheus/latest/querying/operators/#aggregation-operators
    "count",
    "sum",
    "min",
    "max",
    "bottomk",
    "topk",
    "limitk",
    "limit_ratio",
    "group",
    "count_values",
    "stddev",
    "stdvar",
    "quantile",
    "*",
    "+",
    "-",
    "/",
    "%",
    "avg",
    # FROM https://prometheus.io/docs/prometheus/latest/querying/functions/
    "abs",
    "absent",
    "absent_over_time",
    "ceil",
    "changes",
    "clamp",
    "clamp_max",
    "clamp_min",
    "day_of_month",
    "day_of_week",
    "day_of_year",
    "days_in_month",
    "delta",
    "deriv",
    "double_exponential_smoothing",
    "exp",
    "floor",
    "histogram_avg",
    "histogram_count",
    "histogram_sum",
    "histogram_fraction",
    "histogram_quantile",
    "histogram_stddev",
    "histogram_stdvar",
    "hour",
    "idelta",
    "increase",
    "info",
    "irate",
    "label_join",
    "label_replace",
    "ln",
    "log2",
    "log10",
    "minute",
    "month",
    "predict_linear",
    "rate",
    "resets",
    "round",
    "scalar",
    "sgn",
    "sort",
    "sort_desc",
    "sort_by_label",
    "sort_by_label_desc",
    "sqrt",
    "time",
    "timestamp",
    "vector",
    "year",
    "aggregation_over_time",
    # Trigonometric Functions
    "acos",
    "acosh",
    "asin",
    "asinh",
    "atan",
    "atanh",
    "cos",
    "cosh",
    "sin",
    "sinh",
    "tan",
    "tanh",
    "deg",
    "pi",
    "rad",
)


def deduplicate(func) -> List:
    @wraps(func)
    def parse2list(self) -> List:
        return list(parse(self))

    def parse(self) -> Iterable[str]:
        seen = set([])
        for m in func(self):
            b64 = base64.b64encode(str(m).encode("utf8"))
            if b64 in seen:
                continue
            seen.add(b64)
            yield m

    return parse2list


def functionsnolabels(func) -> List:
    @wraps(func)
    def parse2list(self) -> List:
        return list(parse(self))

    def parse(self) -> Iterable:
        for m in func(self):
            if m.get("name") in PromQLFunctions:
                m = {"name": m.get("name")}
            yield m

    return parse2list


def withvalues(func):
    @wraps(func)
    def addvalues(self):
        for metric in func(self):
            if self.values != []:
                yield {"metric": metric, "values": self.values}
            yield {"metric": metric}

    return addvalues


def PromQL_safe(name) -> str:
    # [a-zA-Z_:][a-zA-Z0-9_:]*
    safe_chars = string.ascii_lowercase + string.digits + "_:"
    return "".join(list(map(lambda x: x if x.lower() in safe_chars else "_", name)))


class PromQL(object):
    def __init__(self, query: List = [Self]) -> None:
        self.query = query
        self.object = None
        self._subobjects = set([])
        self.matchers = set([])

    @classmethod
    def parse(cls, pql: str | Self | Dict) -> Self:
        """parse promql_parser Classes and Types to objects"""
        try:
            if isinstance(pql, str):
                pql = promql_parser.parse(pql)
        except Exception as pqlerr:
            if pql.startswith("label{"):
                try:
                    pql = promql_parser.parse(pql[5:])
                except Exception as pqlerr:
                    raise PromQLException(pqlerr)
            else:
                raise PromQLException(pqlerr)
        if isinstance(pql, promql_parser.BinaryExpr):
            return PromQLBinaryExpr(pql)
        elif isinstance(pql, promql_parser.Call):
            return PromQLCall(pql)
        elif isinstance(pql, promql_parser.Function):
            return PromQLFunction(pql)
        elif isinstance(pql, promql_parser.MatrixSelector):
            return PromQLMatrixSelector(pql)
        elif isinstance(pql, promql_parser.NumberLiteral):
            return PromQLNumberLiteral(pql)
        elif isinstance(pql, promql_parser.StringLiteral):
            return PromQLStringLiteral(pql)
        elif isinstance(pql, promql_parser.SubqueryExpr):
            return PromQLSubqueryExpr(pql)
        elif isinstance(pql, promql_parser.UnaryExpr):
            return PromQLUnaryExpr(pql)
        elif isinstance(pql, promql_parser.VectorMatchCardinality):
            return PromQLVectorMatchCardinality(pql)
        elif isinstance(pql, promql_parser.VectorSelector):
            return PromQLVectorSelector(pql)
        elif isinstance(pql, promql_parser.AggregateExpr):
            return PromQLAggregateExpr(pql)
        elif isinstance(pql, promql_parser.ParenExpr):
            return PromQLParenExpr(pql)
        elif isinstance(pql, promql_parser.Expr):
            return PromQLExpr(pql)
        elif isinstance(pql, PromQL):
            return pql
        if isinstance(pql, dict):
            # try building from repsonse dict a PromQL object
            # try:
            if True:
                # if pql.get("metric", {}).get("name", False) is not False:
                #    name = pql.get("metric").get("name")
                #    del pql["metric"]["name"]
                # else:
                name = ""
                # print(f"{cls} pql.get {pql.get('metric', pql).items()}")
                d2s = (
                    name
                    + "{"
                    + ",".join(
                        list(
                            map(
                                lambda x: x[0] + "=" + '"' + x[1] + '"',
                                pql.get("metric", pql).items(),
                            )
                        )
                    )
                    + "}"
                )
                return PromQL.parse(d2s)
            try:
                pass
            except Exception:
                logger.error(f"pql Exception on {pql}", level=3)
                raise PromQLException(f"unknown PromQL Type {type(pql)} {pql}")
        else:
            logger.error(f"unknown PromQL Type {type(pql)} {pql}", level=3)
            raise PromQLException(f"unknown PromQL Type {type(pql)} {pql}")

    @property
    def b64(self) -> ByteString:
        return base64.b64encode(self.query.prettify().encode("utf8"))

    @property
    def name(self) -> str:
        """return the name of the metric, function, ..."""
        raise PromQLException(f"Name Not Implemented {__class__.__name__}")

    @deduplicate
    @functionsnolabels
    def to_dict(self) -> Iterable[dict]:
        """return promql_parser objects to dictionary objects"""
        labels, data = {}, []
        for label in map(lambda x: x.matchers, self._get_subobjects()):
            try:
                labels.update(label.to_dict())
            except:
                logger.debug(f"cannot convert label to dict {label}", level=999)

        for label in map(lambda x: x.to_dict(), self.matchers):
            labels.update(label)

        try:
            sdata = {"name": self.name}
            sdata.update(labels)
            data = [sdata]
        except PromQLException:
            pass
        if all([labels.get("__name__", False) is not False, data != []]):
            data[0]["name"] = labels["__name__"]
            del data[0]["__name__"]

        try:
            return data + list(
                map(
                    lambda x: {"name": x.name} | labels,
                    self._get_subobjects(name=False),
                )
            )
        except Exception:
            return data + list(
                map(
                    lambda x: {"name": x.name} | labels, self._get_subobjects(name=True)
                )
            )

    @deduplicate
    def get_names(self, functions: bool = False) -> str:
        for n in self._get_subobjects(name=True):
            if all([n.name in PromQLFunctions, functions == False]):
                continue
            yield n.name

    def has_subobjects(self, name: bool = False) -> bool:
        if list(self._subobjects) == []:
            return False
        return True

    def _get_subobjects(self, name: bool = False) -> Iterable[Self]:
        for s in self._subobjects:
            if s.has_subobjects(name=name):
                for ss in s._get_subobjects(name=name):
                    yield ss
                    continue
            if name is True:
                try:
                    s.name
                    yield s
                except PromQLException:
                    continue
            else:
                yield s

    @property
    def to_str(self) -> str:
        return " ".join(self.object.prettify().strip().split())

    def enforce_new(self, pql=None) -> Self:
        for m in pql.matchers:
            try:
                old = list(filter(lambda x: x.name == m.name, self.matchers))[0]
                if any([not old.value in m.value,
                        old.value == '']):
                    new = m.to_str
                    self = PromQL.parse(self.object.prettify().replace(old.to_str, new))
                    return self
                continue
            except IndexError:
                if len(self.matchers) == 0:
                    old = self.to_str
                    if "}" in old:
                        new = old.replace("}", "}" + m.to_str + "}")
                    else:
                        new = "{" + f'__name__="{old}",{m.to_str}' + "}"
                elif len(self.matchers) > 0:
                    old = list(self.matchers)[0].to_str
                    new = f"{old},{m.to_str}"
                else:
                    old = list(self.matchers)[0].to_str
                    new = m.to_str
                #print(f"old {old} -> new {new}")
                newp = self.object.prettify().replace(old, new)
                self = PromQL.parse(newp)
                #print(f"self {self.to_str}")
        return self

    def __cmp__(self, other: Self) -> bool:
        if isinstance(other, PromQL):
            return self.b64 == other.b64
        else:
            return False

    def __eq__(self, other):
        return self.__cmp__(other)

    def __hash__(self):
        return hash(self.b64)

    def __iter__(self) -> Iterable[Self]:
        yield self


class PromQLAggModifier(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLAggModifier, self).__init__(query)


class PromQLAggModifierType(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLAggModifierType, self).__init__(query)


class PromQLAggregateExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLAggregateExpr, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if self.object.op == None:
            return "label"
        return str(self.object.op)

    def parse(self, pql: str | Self | dict) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            try:
                for k in ("expr", "args", "func"):
                    expr = getattr(self.object, k, False)
                    if not expr is False:
                        object = super(PromQLAggregateExpr, self).parse(expr)
                        self.matchers.update(object.matchers)
                        self._subobjects.update(object)
            except PromQLException as err:
                logger.debug(f"{self} EXPR exception {err}", level=3)
                pass
        except PromQLException as perr:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLAtModifier(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLAtModifier, self).__init__(query)


class PromQLAtModifierType(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLAggModifierType).__init__(query)


class PromQLBinModifier(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLBinModifier, self).__init__(query)


class PromQLBinaryExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLBinaryExpr, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if self.object.op == None:
            return "label"
        return str(self.object.op)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            expr = self.object
            for side in ("lhs", "rhs"):
                for _ in range(10):
                    nside = super(PromQLBinaryExpr, self).parse(getattr(expr, side))
                    self.matchers.update(nside.matchers)
                    self._subobjects.update(nside)
                    break
        except PromQLException as err:
            PromQLException(pql)
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLCall(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLCall, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if self.object.func.name == None:
            return "label"
        return str(self.object.func.name)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            for expr in self.object.args:
                object = super(PromQLCall, self).parse(expr)
                self.matchers.update(object.matchers)
                self._subobjects.update(object)
        except PromQLException as err:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLExpr, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if self.object.op == None:
            return "label"
        return str(self.object.op)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql.object
        try:
            object = super(PromQLExpr, self).parse(self.object)
            self.matchers.update(object.matchers)
            self._subobjects.update(object)
        except PromQLException as err:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLFunction(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLFunction, self).__init__(query)


class PromQLLabelModifier(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLLabelModifier, self).__init__(query)


class PromQLLabelModifierType(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLLabelModifierType, self).__init__(query)


class PromQLMatchOp(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLMatchOp, self).__init__(query)


class PromQLMatcher(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLMatcher, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if self.object.op == None:
            return "label"
        return self.object.name

    @property
    def value(self) -> str:
        return self.object.value

    @property
    def b64(self) -> ByteString:
        return base64.b64encode(f"{self.name}{self.value}".encode("utf8"))

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        return self

    def items(self) -> Tuple:
        return (self.name, self.value)

    def to_dict(self) -> Dict:
        return {self.name: self.value}

    @property
    def op_to_str(self) -> str:
        if self.object.op == promql_parser.MatchOp.Re:
            return "=~"
        elif self.object.op == promql_parser.MatchOp.NotRe:
            return "!~"
        elif self.object.op == promql_parser.MatchOp.Equal:
            return "="
        elif self.object.op == promql_parser.MatchOp.NotEqual:
            return "!="

    @property
    def to_str(self) -> str:
        return self.name + self.op_to_str + f'"{self.value}"'


class PromQLMatchers(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLMatchers, self).__init__(query)
        self.parse(query)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        try:
            for matcher in pql.matchers:
                self.matchers.add(PromQLMatcher(matcher))
        except PromQLException:
            pass
        return self

    def to_dict(self) -> Dict:
        data = {}
        for m in self:
            data.update(m.to_dict())
        return data

    def items(self) -> Iterable[Tuple]:
        for m in self:
            yield m.items()

    def __iter__(self) -> Iterable[Self]:
        for m in self.matchers:
            yield m

    def __len__(self):
        return len(self.matchers)


class PromQLMatrixSelector(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLMatrixSelector, self).__init__(query)
        self.parse(query)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            expr = self.object.vector_selector
            object = super(PromQLMatrixSelector, self).parse(expr)
            if isinstance(object, PromQLMatrixSelector):
                object = super(PromQLMatrixSelector, self).parse(object.expr)
            self.matchers.update(object.matchers)
            self._subobjects.update(object)
        except PromQLException as err:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLNumberLiteral(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLNumberLiteral, self).__init__(query)


class PromQLParenExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLParenExpr, self).__init__(query)
        self.parse(query)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            expr = self.object
            for side in ("lhs", "rhs"):
                for _ in range(10):
                    try:
                        nside = super(PromQLParenExpr, self).parse(
                            getattr(expr.expr, side)
                        )
                    except Exception:
                        nside = super(PromQLParenExpr, self).parse(
                            getattr(expr.expr, "expr")
                        )
                    if isinstance(nside, PromQLCall):
                        nside = super(PromQLParenExpr, self).parse(nside)
                    elif isinstance(nside, PromQLBinaryExpr):
                        nside = super(PromQLParenExpr, self).parse(nside)
                    elif isinstance(nside, PromQLParenExpr):
                        nside = super(PromQLParenExpr, self).parse(nside)
                    elif isinstance(nside, PromQLExpr):
                        nside = super(PromQLParenExpr, self).parse(nside)
                    self.matchers.update(nside.matchers)
                    self._subobjects.update(nside)
                    break
        except Exception as parseerr:
            try:
                nside = super(PromQLParenExpr, self).parse(self.object.expr.expr)
            except Exception as parseerr:
                nside = super(PromQLParenExpr, self).parse(self.object.expr)
            if isinstance(nside, PromQLCall):
                self.matchers.update(nside.matchers)
                self._subobjects.update(nside)
            else:
                raise PromQLException(self.object.prettify())
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLStringLiteral(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLStringLiteral, self).__init__(query)


class PromQLSubqueryExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLSubqueryExpr, self).__init__(query)
        self.parse(query)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            try:
                for k in ("expr", "args", "func"):
                    expr = getattr(self.object, k, False)
                    if not expr is False:
                        object = super(PromQLSubqueryExpr, self).parse(expr)
                        self.matchers.update(object.matchers)
                        self._subobjects.update(object)
            except PromQLException as err:
                pass
        except PromQLException as err:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self


class PromQLTokenType(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLTokenType, self).__init__(query)


class PromQLUnaryExpr(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLUnaryExpr, self).__init__(query)


class PromQLValueType(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLValueType, self).__init__(query)


class PromQLVectorMatchCardinality(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLVectorMatchCardinality, self).__init__(query)


class PromQLVectorSelector(PromQL):
    def __init__(self, query: List[Self] = None) -> Self:
        super(PromQLVectorSelector, self).__init__(query)
        self.parse(query)

    @property
    def name(self) -> str:
        if all([self.object.name == None, len(self.get_names()) > 0]):
            return "label"
        elif "alertname" in self.get_names():
            return "alert"
        elif self.object.name == None:
            # wildcard metric query assumption
            return "metric"
        return str(self.object.name)

    def parse(self, pql: str | dict | Self) -> Self:
        """parse promql_parser Classes and Types to objects"""
        self.object = pql
        try:
            self.matchers = PromQLMatchers(pql.matchers)
        except PromQLException:
            pass
        logger.debug(f"{self} {list(self._subobjects)}", level=3)
        return self
