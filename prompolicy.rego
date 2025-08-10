package abac

default allow := false

_has_ns_key := object.get(input, ["metric", "namespace"], false)
_has_cluster_key := object.get(input, ["metric", "cluster"], false)
_is_function if input.metric.kind == "function"

cluster := input.metric.cluster in input.attr.clusterqueries
ns := input.metric.namespace in input.attr.namespacequeries

clusterq if {
	some clu in input.attr.clusterqueries
	regex.match(clu, input.metric.cluster)
}

nsq if {
	some name in input.attr.namespacequeries
	regex.match(name, input.metric.namespace)
}
	
_has_ns_is_valid if {
	_has_ns_key in input.attr.namespacequeries
}

_has_ns_is_valid if {
	_has_ns_key == false
}

_has_cluster_is_valid if {
	_has_cluster_key in input.attr.clusterqueries
}

_has_cluster_is_valid if {
	_has_cluster_key == false
}

_has_cluster_is_valid if clusterq 

_has_ns_is_valid if nsq

allow if _is_function

allow if {
	_has_cluster_is_valid
	_has_ns_is_valid
}
