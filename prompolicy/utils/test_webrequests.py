import pytest
from multidict import MultiDict, MultiDictProxy

from .webrequests import *


def headers():
    return MultiDictProxy(
        MultiDict(
            {
                "Transfer-Encoding": "test",
                "Content-Length": "test",
                "Content-Encoding": "test",
                "Accept-Encoding": "test",
                "Origin": "test",
                "Referer": "test",
                "Host": "test",
                "Vary": "test",
            }
        )
    )


def data():
    return {
        "metric": {
            "__name__": "metric-name",
            "label1": "value1",
            "label2": "value2",
        },
        "values": list(range(100)),
        "value": 42,
    }


def test_headers_01():
    newheaders = adjust_headers(headers())
    assert newheaders == {}


def test_headers_02():
    moreheaders = headers().copy()
    moreheaders["Traceparent"] = "test"
    newheaders = adjust_headers(moreheaders)
    assert newheaders["Traceparent"] == "test"


def test_headers_03():
    newheaders = adjust_headers(headers())
    moreheaders = newheaders.copy()
    moreheaders["another"] = "some"
    newheaders = adjust_headers(moreheaders)
    assert newheaders["another"] == "some"


def test_remap_results_novalues():
    newdata = list(remap_results(data(), values=False))[0]
    assert newdata["metric"]["__name__"] == "metric-name"
    assert newdata["metric"]["label1"] == "value1"
    assert newdata["metric"]["label2"] == "value2"
    with pytest.raises(KeyError):
        newdata["values"]


def test_remap_results_novalue():
    d = data()
    del d["values"]
    newdata = list(remap_results(d, values=False))[0]
    assert newdata["metric"]["__name__"] == "metric-name"
    assert newdata["metric"]["label1"] == "value1"
    assert newdata["metric"]["label2"] == "value2"
    with pytest.raises(KeyError):
        newdata["value"]


def test_remap_results_values():
    newdata = list(remap_results(data(), values=True))[0]
    assert newdata["metric"]["__name__"] == "metric-name"
    assert newdata["metric"]["label1"] == "value1"
    assert newdata["metric"]["label2"] == "value2"
    assert len(newdata["values"]) == 100


def test_remap_results_value():
    d = data()
    del d["values"]
    newdata = list(remap_results(d, values=True))[0]
    assert newdata["metric"]["__name__"] == "metric-name"
    assert newdata["metric"]["label1"] == "value1"
    assert newdata["metric"]["label2"] == "value2"
    assert newdata["value"] == 42


def test_remap_results_withnames():
    d = data()
    del d["metric"]["__name__"]
    newdata = list(remap_results(d, values=True, names=["query-accumulation"]))[0]
    assert newdata["metric"]["__name__"] == "query-accumulation"
    assert newdata["metric"]["label1"] == "value1"
    assert newdata["metric"]["label2"] == "value2"


def test_remap_result_withnames_compare():
    d1 = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"instance": "inst1"},
                    "values": [[1748694390, "0.019499999999970898"]],
                }
            ],
            "analysis": {},
        },
    }
    d2 = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {
                        "__name__": "node_cpu_seconds_total",
                        "instance": "inst1",
                    },
                    "values": [[1748694390, "0.019499999999970898"]],
                }
            ],
            "analysis": {},
        },
    }
    nd1 = list(remap_results(d1["data"]["result"], names=["node_cpu_seconds_total"]))
    nd2 = list(
        remap_results(d2["data"]["result"], names=["node_cpu_seconds_total_broken"])
    )
    assert nd1[0]["metric"]["__name__"] == "node_cpu_seconds_total"
    assert nd2[0]["metric"]["__name__"] == "node_cpu_seconds_total"
