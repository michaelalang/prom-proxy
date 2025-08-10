import json

import pytest

from .generators import *
from .promql import *
from .webrequests import *


def test_promql_exception():
    with pytest.raises(PromQLException):
        PromQL().parse("$$$$")


def test_generator():
    p = PromQL.parse("up")
    c = Metric2Policy(p)
    e = list(c.to_grpc)[0]
    f = e.ListFields()
    assert f[0][1] == "metric"
    assert f[1][1] == p.b64.decode("utf8")
    d = f[2][1]
    assert d["name"] == Value(string_value="up")
    assert sorted(d.keys()) == ["kind", "name", "owner", "public"]


def test_generator_function():
    p = PromQL.parse("sum(rate(up{}[5m]))")
    c = Metric2Policy(p)
    for e in c.to_grpc:
        f = e.ListFields()
        d = f[-1][-1]

        if all(
            [
                d["name"] == Value(string_value="up"),
                d["kind"] == Value(string_value="metric"),
            ]
        ):
            assert True
        elif all(
            [
                d["name"] == Value(string_value="sum"),
                d["kind"] == Value(string_value="function"),
            ]
        ):
            assert True
        elif all(
            [
                d["name"] == Value(string_value="rate"),
                d["kind"] == Value(string_value="function"),
            ]
        ):
            assert True
        else:
            assert False
    p = PromQL.parse(
        """avg(rate(ceph_osd_op_r_latency_sum{job=~"job"}[5m])/on 
                     (ceph_daemon) 
                     rate(ceph_osd_op_r_latency_count{job=~"job"}[5m])*1000)"""
    )
    c = Metric2Policy(p)
    assert (
        len(
            list(
                filter(
                    lambda f: f["kind"] == Value(string_value="function"),
                    (
                        map(
                            lambda x: x[-1][-1],
                            map(lambda y: y.ListFields(), c.to_grpc),
                        )
                    ),
                )
            )
        )
        == 4
    )
    assert (
        len(
            list(
                filter(
                    lambda f: f["kind"] == Value(string_value="metric"),
                    (
                        map(
                            lambda x: x[-1][-1],
                            map(lambda y: y.ListFields(), c.to_grpc),
                        )
                    ),
                )
            )
        )
        == 2
    )


def test_principal():
    p = MetricPrincipal.from_token(
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqTE5KaWlfMkd0RnhSYlptbkFSaVVmMzFySFA1VTFNaGZqV3ZtSXJ3YWlFIn0.eyJleHAiOjE3NDgzNjU1NzYsImlhdCI6MTc0ODM2NTI3NiwianRpIjoib2ZydHJvOmM1NjA5MzRhLWM1YjEtNDU1OC1iYjQxLWNlNTlhOTVjNzAwZSIsImlzcyI6Imh0dHBzOi8vc3NvLmFwcHMuY2hlc3Rlci5hdC9yZWFsbXMvSG9tZSIsImF1ZCI6WyJyZWFsbS1tYW5hZ2VtZW50IiwiYWNjb3VudCJdLCJzdWIiOiI3NTRkMDY0Yy03MGMzLTQzNGYtYmFkNi01YWY5YmM2NGFhZDgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJIb21lIiwic2lkIjoiZTM1MWUyMTUtNjhkMC00OWIwLTlhYTUtMjI4NjZhMTI1ZDM2IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiZGVmYXVsdC1yb2xlcy1ob21lIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXJlYWxtIiwidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJtYW5hZ2UtaWRlbnRpdHktcHJvdmlkZXJzIiwiaW1wZXJzb25hdGlvbiIsInJlYWxtLWFkbWluIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBvZmZsaW5lX2FjY2VzcyBwcm9maWxlIG9yZ2FuaXphdGlvbiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiTWljaGFlbGEgTGFuZyIsImdyb3VwcyI6WyJBZG1pbiIsImFsbHVzZXJzIiwiZ2l0ZWEtYWRtaW4iLCJtaWxhbmciLCJvY3BhZG1pbnMiLCJvcmdhMSIsInF1YXktc3VwZXJ1c2VycyIsInJnd2FkbWlucyIsInN1cGVydXNlciIsIndoZWVsIl0sInByZWZlcnJlZF91c2VybmFtZSI6Im1pbGFuZyIsImdpdmVuX25hbWUiOiJNaWNoYWVsYSBMYW5nIiwiZW1haWwiOiJtaWxhbmdAcmVkaGF0LmNvbSIsInVzZXJuYW1lIjoibWlsYW5nIn0.afDiK1ctZkb8MP2n7bO2eXTc6-8ldv97Brh1DkyKq0iN1mZ3KbLaHdGKJexku3f5dCLK-tkbN8_-h5tmU4lkmdEIwA40dtnX5tX6Ujm7A6Y7oaiSYGpwTLBYih30nGowfZjX-KWl6XNKoqQFo4loIBPmo72JH-4mX7mdQzY690f1wiTbdu6o0GOQz0Xu3EaXoJbKa5W7sZHTP9SOjFgSVWhWfM3RkdPgkQU9Hd729z0vIb5EKKLmNGwfT8k6gteJ9Zpbtion1oUBVfFF-fESpvu7qZPSVBIY2E5Qg4dTZH0UgM01I6ljq27iGhFYaaaVsnB6L5a_CJCaUhL2qYWv3Q",
        do_time_check=False,
    )
    assert isinstance(p, MetricPrincipal)
    assert p.name == "milang"
    assert sorted(p.groups) == [
        "Admin",
        "allusers",
        "gitea-admin",
        "milang",
        "ocpadmins",
        "orga1",
        "quay-superusers",
        "rgwadmins",
        "superuser",
        "wheel",
    ]
    assert sorted(p.token.keys()) == [
        "acr",
        "allowed-origins",
        "aud",
        "azp",
        "email",
        "email_verified",
        "exp",
        "given_name",
        "groups",
        "iat",
        "iss",
        "jti",
        "name",
        "preferred_username",
        "realm_access",
        "resource_access",
        "scope",
        "sid",
        "sub",
        "typ",
        "username",
    ]


def test_metricsfactory():
    m = MetricsFactory.from_dict(
        [
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "idle",
                }
            },
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "iowait",
                }
            },
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "irq",
                }
            },
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "nice",
                }
            },
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "softirq",
                }
            },
            {
                "metric": {
                    "cluster": "us-east-1",
                    "cpu": "8",
                    "instance": "inst1",
                    "job": "node",
                    "mode": "steal",
                }
            },
        ]
    )
    assert isinstance(m, MetricsFactory)
    assert len(m) == 6
    for mm in m:
        assert isinstance(mm, Metric2Policy)
    for mm in m.to_grpc:
        assert isinstance(mm, Metric2Policy)


def test_metricsfactory_from_labels():
    data = [
        "Cache",
        "__name__",
        "action",
        "address",
        "adminstate",
        "after_stage",
        "api",
        "autosync_enabled",
        "baseboard_manufacturer",
        "baseboard_product_name",
        "bios_date",
        "bios_release",
        "bios_vendor",
        "bios_version",
        "board_asset_tag",
        "board_name",
        "board_vendor",
        "board_version",
        "branch",
        "broadcast",
        "bucket",
        "cachesize",
        "call",
        "cause",
        "ceph_daemon",
        "ceph_version",
        "chassis_asset_tag",
        "chassis_vendor",
        "chassis_version",
        "check",
        "chip",
        "chip_name",
        "cipher_suite",
        "clocksource",
        "cluster",
        "cluster_addr",
        "code",
        "collector",
        "command",
        "commit",
        "component",
        "compression_mode",
        "config",
        "connection",
        "controller",
        "core",
        "cpu",
        "data_pools",
        "data_type",
        "description",
        "dest_namespace",
        "dest_server",
        "device",
        "device_class",
        "device_error",
        "device_ids",
        "devicename",
        "devices",
        "devicetype",
        "dialer_name",
        "direction",
        "domainname",
        "downstream",
        "duplex",
        "endpoint",
        "entitites",
        "envoy_cluster_name",
        "envoy_http_conn_manager_prefix",
        "envoy_listener_address",
        "envoy_response_code",
        "envoy_response_code_class",
        "envoy_tcp_prefix",
        "envoy_worker_id",
        "event",
        "exported_instance",
        "failed",
        "family",
        "file",
        "fingerprint_sha256",
        "firmware_revision",
        "fs_id",
        "fstype",
        "gateway",
        "generation",
        "goarch",
        "goos",
        "governor",
        "goversion",
        "group",
        "grpc_code",
        "grpc_method",
        "grpc_service",
        "grpc_type",
        "handler",
        "hardwareversion",
        "health_status",
        "host",
        "hostname",
        "id",
        "id_like",
        "identity",
        "implementation",
        "initiator",
        "instance",
        "instance_id",
        "interface",
        "interfacetype",
        "interval",
        "ip",
        "ipaddress",
        "issuer",
        "item_type",
        "job",
        "k8s_version",
        "kind",
        "label",
        "le",
        "listener_name",
        "macaddress",
        "machine",
        "major",
        "mechanism",
        "metadata_pool",
        "method",
        "microcode",
        "minor",
        "mode",
        "model",
        "model_name",
        "modelname",
        "modified",
        "mountpoint",
        "name",
        "namespace",
        "nodename",
        "objectstore",
        "op",
        "operation",
        "operstate",
        "package",
        "patchlevel",
        "path",
        "phase",
        "pool",
        "pool_id",
        "port",
        "pretty_name",
        "product_family",
        "product_name",
        "product_sku",
        "product_version",
        "productclass",
        "project",
        "proto",
        "protocol",
        "public_addr",
        "quantile",
        "queue",
        "ram_type",
        "range",
        "rank",
        "reason",
        "release",
        "replica",
        "repo",
        "resource_kind",
        "response_code",
        "revision",
        "role",
        "scrape_job",
        "sensor",
        "serial",
        "serialnumber",
        "server",
        "service",
        "set",
        "severity",
        "slice",
        "softwareversion",
        "source",
        "stage",
        "state",
        "status",
        "stepping",
        "subject",
        "subjectalternative",
        "sync_status",
        "sysname",
        "system_manufacturer",
        "system_product_name",
        "system_vendor",
        "system_version",
        "tag",
        "tags",
        "target_id",
        "tenant",
        "thread_state",
        "time_zone",
        "tplink_sg_switch_port_linkSpeed",
        "tplink_sg_switch_port_linkState",
        "type",
        "unit",
        "upstream",
        "user",
        "variant",
        "variant_id",
        "vendor",
        "verb",
        "version",
        "version_id",
        "wlan",
        "wwn",
        "zone",
    ]
    m = MetricsFactory.from_dict(
        map(lambda x: {"metric": {"name": PromQL_safe(x), "kind": "label"}}, data)
    )
    for mm in m:
        assert isinstance(mm, Metric2Policy)
    for mm in m.to_grpc:
        assert isinstance(mm, Metric2Policy)
    for d in m.to_dict:
        assert isinstance(d, dict)
        assert d.get("kind", "label") == "label"


def test_metricsfactory_filtered():
    data = [
        "Cache",
        "__name__",
        "action",
        "address",
        "adminstate",
        "after_stage",
        "api",
        "autosync_enabled",
        "baseboard_manufacturer",
        "baseboard_product_name",
        "bios_date",
        "bios_release",
        "bios_vendor",
        "bios_version",
        "board_asset_tag",
        "board_name",
        "board_vendor",
        "board_version",
        "branch",
        "broadcast",
        "bucket",
        "cachesize",
        "call",
        "cause",
        "ceph_daemon",
        "ceph_version",
        "chassis_asset_tag",
        "chassis_vendor",
        "chassis_version",
        "check",
        "chip",
        "chip_name",
        "cipher_suite",
        "clocksource",
        "cluster",
        "cluster_addr",
        "code",
        "collector",
        "command",
        "commit",
        "component",
        "compression_mode",
        "config",
        "connection",
        "controller",
        "core",
        "cpu",
        "data_pools",
        "data_type",
        "description",
        "dest_namespace",
        "dest_server",
        "device",
        "device_class",
        "device_error",
        "device_ids",
        "devicename",
        "devices",
        "devicetype",
        "dialer_name",
        "direction",
        "domainname",
        "downstream",
        "duplex",
        "endpoint",
        "entitites",
        "envoy_cluster_name",
        "envoy_http_conn_manager_prefix",
        "envoy_listener_address",
        "envoy_response_code",
        "envoy_response_code_class",
        "envoy_tcp_prefix",
        "envoy_worker_id",
        "event",
        "exported_instance",
        "failed",
        "family",
        "file",
        "fingerprint_sha256",
        "firmware_revision",
        "fs_id",
        "fstype",
        "gateway",
        "generation",
        "goarch",
        "goos",
        "governor",
        "goversion",
        "group",
        "grpc_code",
        "grpc_method",
        "grpc_service",
        "grpc_type",
        "handler",
        "hardwareversion",
        "health_status",
        "host",
        "hostname",
        "id",
        "id_like",
        "identity",
        "implementation",
        "initiator",
        "instance",
        "instance_id",
        "interface",
        "interfacetype",
        "interval",
        "ip",
        "ipaddress",
        "issuer",
        "item_type",
        "job",
        "k8s_version",
        "kind",
        "label",
        "le",
        "listener_name",
        "macaddress",
        "machine",
        "major",
        "mechanism",
        "metadata_pool",
        "method",
        "microcode",
        "minor",
        "mode",
        "model",
        "model_name",
        "modelname",
        "modified",
        "mountpoint",
        "name",
        "namespace",
        "nodename",
        "objectstore",
        "op",
        "operation",
        "operstate",
        "package",
        "patchlevel",
        "path",
        "phase",
        "pool",
        "pool_id",
        "port",
        "pretty_name",
        "product_family",
        "product_name",
        "product_sku",
        "product_version",
        "productclass",
        "project",
        "proto",
        "protocol",
        "public_addr",
        "quantile",
        "queue",
        "ram_type",
        "range",
        "rank",
        "reason",
        "release",
        "replica",
        "repo",
        "resource_kind",
        "response_code",
        "revision",
        "role",
        "scrape_job",
        "sensor",
        "serial",
        "serialnumber",
        "server",
        "service",
        "set",
        "severity",
        "slice",
        "softwareversion",
        "source",
        "stage",
        "state",
        "status",
        "stepping",
        "subject",
        "subjectalternative",
        "sync_status",
        "sysname",
        "system_manufacturer",
        "system_product_name",
        "system_vendor",
        "system_version",
        "tag",
        "tags",
        "target_id",
        "tenant",
        "thread_state",
        "time_zone",
        "tplink_sg_switch_port_linkSpeed",
        "tplink_sg_switch_port_linkState",
        "type",
        "unit",
        "upstream",
        "user",
        "variant",
        "variant_id",
        "vendor",
        "verb",
        "version",
        "version_id",
        "wlan",
        "wwn",
        "zone",
    ]
    m = MetricsFactory.from_dict(
        map(lambda x: {"metric": {"name": PromQL_safe(x), "kind": "label"}}, data)
    )

    seen = list(
        map(lambda x: base64.b64encode(str(x).encode("utf8")).decode("utf8"), m.to_dict)
    )
    for d in m.to_dict:
        if base64.b64encode(str(d).encode("utf8")).decode("utf8") in seen:
            continue
        assert d == True

    seen = seen[: int(len(seen) / 2)]
    newdata = []
    for d in m.to_dict:
        if base64.b64encode(str(d).encode("utf8")).decode("utf8") in seen:
            continue
        newdata.append(d)
    assert len(seen) != len(newdata)
    assert (len(list(m.to_dict)) - len(seen)) == len(newdata)


def test_metricsfactory_from_response():
    data = json.loads(
        '{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"node_cpu_seconds_total","cluster":"us-east-1","cpu":"0","instance":"retropie.example.com:9100","job":"node","mode":"idle"},"values":[1,2,3,4,5]}]}}'
    )
    mdata = data.get("data")
    m = MetricsFactory.from_dict(remap_results(mdata.get("result"), values=True))
    assert len(m) == 1
    assert len(list(m.to_dict)) == 1
    assert sorted(list(m.to_dict)[0].keys()) == [
        "cluster",
        "cpu",
        "instance",
        "job",
        "mode",
        "name",
    ]

def test_alertnames():
    p = PromQL.parse('{alertname="CDIDataImportCronOutdated"}')
    c = Metric2Policy(p)
    e = list(c.to_grpc)[0]
    f = e.ListFields()
    assert f[0][1] == "alert"
    assert f[1][1] == p.b64.decode("utf8")
    d = f[2][1]
    assert d["alertname"] == Value(string_value="CDIDataImportCronOutdated")
    assert d["name"] == Value(string_value="alertname")
    #print(e)

def test_alerttype():
    p = PromQL.parse('sum(ALERTS{alertstate="firing", severity=~".*"}) by (cluster, alertname, severity)')
    c = Metric2Policy(p)
    e = list(c.to_grpc)[1]
    f = e.ListFields()
    assert f[0][1] == "alert"

