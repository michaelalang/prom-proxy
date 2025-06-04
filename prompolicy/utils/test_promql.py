import pytest

from ..exceptions import *
from .promql import *


def test_promql_exception():
    with pytest.raises(PromQLException):
        PromQL().parse("$$$$")


def test_promql_b64():
    p = PromQL.parse("up")
    assert p.b64 == b"dXA="
    p1 = PromQL.parse("up")
    assert p == p1
    p2 = PromQL.parse("notup")
    assert p != p2
    assert p1 != p2


def test_promql_vectorselector_nomatchers():
    p = PromQL.parse("up")
    assert isinstance(p, PromQLVectorSelector)
    assert p.name == "up"
    assert p.to_dict() == [{"name": "up"}]
    assert len(p.matchers) == 0


def test_promql_vectorselector_matchers():
    p = PromQL.parse('up{instance="node1",job="node-exporter"}')
    assert isinstance(p, PromQLVectorSelector)
    assert p.name == "up"
    assert len(p.matchers) == 2
    assert p.to_dict() == [{"name": "up", "instance": "node1", "job": "node-exporter"}]


def test_promql_call():
    p = PromQL.parse(
        'increase(gateway_traffic{direction="Received",unit="Bytes", interface="WAN"}[5m])'
    )
    assert isinstance(p, PromQLCall)
    assert p.name == "increase"
    assert len(p.matchers) == 3
    assert sorted(p.to_dict()[0].keys()) == ["name"]
    assert sorted(p.to_dict()[1].keys()) == sorted(
        {
            "name": "increase",
            "unit": "Bytes",
            "interface": "WAN",
            "direction": "Received",
        }.keys()
    )


def test_promql_matrixselector():
    p = PromQL.parse(
        'increase(gateway_traffic{direction="Received",unit="Bytes", interface="WAN"}[5m])'
    )
    m = list(p._subobjects)[0]
    assert isinstance(m, PromQLMatrixSelector)
    with pytest.raises(PromQLException):
        m.name
    assert len(m.matchers) == 3
    assert m.to_dict() == [
        {
            "direction": "Received",
            "interface": "WAN",
            "name": "gateway_traffic",
            "unit": "Bytes",
        }
    ]


def test_promql_matchers():
    p = PromQL.parse(
        'increase(gateway_traffic{direction="Received",unit="Bytes", interface="WAN"}[5m])'
    )
    assert len(p.matchers) == 3
    for matcher in p.matchers:
        assert isinstance(matcher.items(), tuple)
    for matcher in p.matchers:
        assert isinstance(matcher.to_dict(), dict)
    matcher = list(filter(lambda x: x.name == "interface", p.matchers))[0]
    assert matcher.items() == ("interface", "WAN")
    matcher = list(filter(lambda x: x.name == "direction", p.matchers))[0]
    assert matcher.to_dict() == {"direction": "Received"}


def test_promql_matchers_duplication():
    p = PromQL.parse(
        'increase(gateway_traffic{direction="Received",unit="Bytes", interface="WAN"}[5m])'
    )
    assert len(p.matchers) == 3
    pp = PromQL.parse(
        'increase(gateway_traffic{something="new",unit="Bytes", interface="WAN"}[5m])'
    )
    assert len(pp.matchers) == 3
    p.matchers.update(pp.matchers)
    assert len(p.matchers) == 4


def test_promql_matcher():
    p = PromQL.parse(
        'increase(gateway_traffic{direction="Received",unit="Bytes", interface="WAN"}[5m])'
    )
    matchers = list(p.matchers)
    matcher = list(filter(lambda x: x.name == "interface", p.matchers))[0]
    assert matcher.name == "interface"
    assert matcher.value == "WAN"
    matcher = list(filter(lambda x: x.name == "direction", p.matchers))[0]
    assert matcher.name == "direction"
    assert matcher.value == "Received"
    matcher = list(filter(lambda x: x.name == "unit", p.matchers))[0]
    assert matcher.name == "unit"
    assert matcher.value == "Bytes"


def test_promql_subquery_expr():
    p = PromQL.parse(
        "max_over_time(deriv(rate(distance_covered_total[5s])[30s:5s])[10m:])"
    )
    assert isinstance(p, PromQLCall)
    assert len(p.matchers) == 0
    assert sorted((map(lambda x: x["name"], p.to_dict()))) == [
        "deriv",
        "distance_covered_total",
        "max_over_time",
        "rate",
    ]
    pp = PromQL.parse(p.object.args[0])
    assert isinstance(pp, PromQLSubqueryExpr)
    assert len(pp.matchers) == 0
    assert sorted((map(lambda x: x["name"], pp.to_dict()))) == [
        "deriv",
        "distance_covered_total",
        "rate",
    ]


def test_promql_subquery_expr_labels():
    p = PromQL.parse(
        'max_over_time(deriv(rate(distance_covered_total{instance="test"}[5s])[30s:5s])[10m:])'
    )
    assert isinstance(p, PromQLCall)
    assert len(p.matchers) == 1
    assert set((map(lambda x: x.get("instance", None), p.to_dict()))) == set(
        ["test", None]
    )


def test_promql_aggregate_expr():
    p = PromQL.parse("sum by (job) (rate(http_requests_total[5m]))")
    assert isinstance(p, PromQLAggregateExpr)
    assert len(p.matchers) == 0
    assert sorted(map(lambda x: x.get("name"), p.to_dict())) == [
        "http_requests_total",
        "rate",
        "sum",
    ]


def test_promql_aggregate_expr_labels():
    p = PromQL.parse(
        'sum by (job) (rate(http_requests_total{instance="node1", job="node-exporter"}[5m]))'
    )
    assert isinstance(p, PromQLAggregateExpr)
    assert len(p.matchers) == 2
    assert sorted(map(lambda x: x.get("name"), p.to_dict())) == [
        "http_requests_total",
        "rate",
        "sum",
    ]
    assert set(map(lambda x: x.get("instance"), p.to_dict())) == set(["node1", None])
    assert set(map(lambda x: x.get("job"), p.to_dict())) == set(["node-exporter", None])


def test_promql_binary_expr():
    p = PromQL.parse(
        "(instance_memory_limit_bytes - instance_memory_usage_bytes) / 1024 / 1024"
    )
    assert isinstance(p, PromQLBinaryExpr)
    assert len(p.matchers) == 0
    assert sorted(set(map(lambda x: x.get("name"), p.to_dict()))) == [
        "/",
        "instance_memory_limit_bytes",
        "instance_memory_usage_bytes",
    ]


def test_promql_binary_expr_labels():
    p = p = PromQL.parse(
        '(instance_memory_limit_bytes{job="node",instance="inst1"} - instance_memory_usage_bytes{job="node", instance="inst1"}) / 1024 / 1024'
    )
    assert isinstance(p, PromQLBinaryExpr)
    assert len(p.matchers) == 2
    assert sorted(set(map(lambda x: x.get("name"), p.to_dict()))) == [
        "/",
        "instance_memory_limit_bytes",
        "instance_memory_usage_bytes",
    ]
    assert set(map(lambda x: x.get("job"), p.to_dict())) == set(["node", None])
    assert set(map(lambda x: x.get("instance"), p.to_dict())) == set([None, "inst1"])


def test_promql_deduplication():
    p = PromQL.parse(
        'topk(10,\n  sum(\n    rate(ceph_rbd_write_latency_sum{job=~".+"}[1m0s]) /\n      clamp_min(rate(ceph_rbd_write_latency_count{job=~".+"}[1m0s]), 1) +\n      rate(ceph_rbd_read_latency_sum{job=~".+"}[1m0s]) /\n      clamp_min(rate(ceph_rbd_read_latency_count{job=~".+"}[1m0s]), 1)\n  ) by (pool, image, namespace)\n)\n'
    )
    assert len(p.to_dict()) == 10


def test_promql_parenexpr_call_handling():
    p = PromQL.parse(
        'sum by(instance) (irate(node_cpu_guest_seconds_total{instance="node1",job="node", mode="user"}[1m])) / on(instance) group_left sum by (instance)((irate(node_cpu_seconds_total{instance="node1",job="node"}[1m])))'
    )
    assert len(p.to_dict()) == 5


def test_promql_dict_to_promql():
    d = {
        "metric": {
            "cluster": "us-east-1",
            "cpu": "0",
            "instance": "node1",
            "job": "node",
            "mode": "idle",
        }
    }
    p = PromQL.parse(d)
    assert isinstance(p, PromQLVectorSelector)
    assert len(p.matchers) == 5
    assert p.name == "label"

    d = {
        "metric": {
            "cluster": "us-east-1",
            "cpu": "0",
            "instance": "node1",
            "job": "node",
            "mode": "idle",
            "name": "node_cpu_seconds_total",
        }
    }
    p = PromQL.parse(d)
    assert isinstance(p, PromQLVectorSelector)
    assert len(p.matchers) == 5
    assert p.name == "node_cpu_seconds_total"


def test_promql_get_names():
    p = PromQL.parse(
        'topk(10,\n  sum(\n    rate(ceph_rbd_write_latency_sum{job=~".+"}[1m0s]) /\n      clamp_min(rate(ceph_rbd_write_latency_count{job=~".+"}[1m0s]), 1) +\n      rate(ceph_rbd_read_latency_sum{job=~".+"}[1m0s]) /\n      clamp_min(rate(ceph_rbd_read_latency_count{job=~".+"}[1m0s]), 1)\n  ) by (pool, image, namespace)\n)\n'
    )
    assert sorted(p.get_names()) == [
        "ceph_rbd_read_latency_count",
        "ceph_rbd_read_latency_sum",
        "ceph_rbd_write_latency_count",
        "ceph_rbd_write_latency_sum",
    ]

    p = PromQL.parse('rate(node_cpu_seconds_total{instance="inst1",job="node"}[5m])')
    assert p.get_names() == ["node_cpu_seconds_total"]
    p = PromQL.parse(
        'rate(node_cpu_seconds_total{instance="inst1",job="node"}[5m]) - rate(something{isntance="inst1",job="node"}[5m])'
    )
    assert sorted(p.get_names()) == ["node_cpu_seconds_total", "something"]
