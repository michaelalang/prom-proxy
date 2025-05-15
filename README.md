# Prometheus fine grained authorization proxy 

This POC is to show-case the possibility we can gain with utilizing state-of-the-art Authorization engines like [cerbos](https://cerbos.dev).

**NOTE** this is not meant for production and since the idea was coming from Red Hat Advanced Cluster Management (RHACM) and in particular, being able to utilize distributed metrics and tenancy, providing shared metrics like infrastructure metrics is mandatory to get a full picture from tenant POV.

With [Perses](https://perses.dev) being the Dashboard engine in RHACM, the POC deploys a standalone Perses instance and the dashboards accordingly.

**NOTE** this Prometheus proxy is not doing **authentication** instead expects a Header that indicates the tenant (and in future version roles). 

The concept of cerbos and the proxy is considered **stateless**. There is no Database or similar necessary which means scaling up and down does not require any additional considerations (except Network connectivity to the Prometheus TSDB instance(s)).

## Policies 

The policies are provide in a separate git repository following best-practice to not share configuration and code base in one repository.
**NOTE** ensure to clone [https://github.com/michaelalang/prom-policies.git](https://github.com/michaelalang/prom-policies.git) if you want to adjust the policies at a later stage.

### splitting policy decisions

PromQL provides **functions** like `sum`, `irate`, `rate`, ... which can be restricted in the file `function.yaml`
The file `metric.yaml` is used to restrict calls before they are executed on the proxied backend. 
`label.yaml` is used when an Aggregation or Expression does not return a metric name.
With wildcard/regex queries like `instance=~".*"` the **response** action is for filtering those on return form the upstream proxy Prometheus.

For the POC the policies are setup and will grant:

* tenant: namespace1
    query: metrics that match `node_cpu_.*` 

* tenant: namespace2
    query: metrics that match `node_cpu_.*` and `node_memory_.*`

* tenant: namespace3
    query: metrics that match `node_cpu_.*`, `node_memory_.*` and `node_disk_.*`

* tenant: namespace4
    query: metrics that match `node_cpu_.*`, `node_memory_.*`, `node_disk_.*` and `node_network_.*`

If you want to experiment with the policies you can extend the section to match only specific instances like

```
    - actions: ["response"]
      effect: EFFECT_ALLOW  
      roles:
        - "user"
      condition:
        match:
          all:
            of:
            - expr: request.principal.id in ["namespace4"]
            - expr: request.resource.attr.instance.matches("system0.*")
```

This would limit the responses returned for tenant `namespace4` to instances that match `system0.*` systems.

## Deployment

### Podman deployment

The POC includes two scripts. One (create_podman_deploy.sh) to deploy a pod and all necessary containers to run it locally.
For deprovisioning the Pod and Containers run delete_podman_deploy.sh accordingly.

The Pod will listen on ports **8081** and **8082** where 8081 is the proxy and 8082 is your perses instance.
Perses datasources included are focused on the OCP deployment and would need adjustment on the URI accordingly.

### OpenShift deployment

The POC has been verified to be deploy and use-able on OpenShift 4.16+ with Cluster Observability operator (COO) 1.1.0+.
You first need to install COO by executing

```
oc create -k ocp/coo-operator
```

After the Operator has been successfully deployed you can instantiate a COO Prometheus Stack and the Proxy with following command

```
oc -n <select-your-namespace> create -k ocp 
```

Ensure to adjust the namespace and the deployment environment variable pointing to your upstream Prometheus instance.
The route CR domain is the last you need to ensure to match your infrastructure. 

Once all those are set correctly, you can start to populate the Perses project, datasources and dashboards with

```
# ensure to adjust the API variable and to include `/api/v1/`
cd perses
API="https://perses.apps.example.com/api/v1/" ./create
cd -
```

