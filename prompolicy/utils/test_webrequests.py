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

def test_remap_results_enforce():
    d = {'metric': {'severity': 'low'}, 'values': [[1753030500, '2'], [1753030800, '2'], [1753031100, '2'], [1753031400, '2'], [1753031700, '2'], [1753032000, '2']]}
    p = PromQL.parse('up{cluster=~"(hcp1|hcp2)"}')
    newdata = list(remap_results(d, pql=p))
    assert newdata[0]["metric"]["cluster"] == "(hcp1|hcp2)"
