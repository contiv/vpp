### Contiv KSR (Kubernetes State Reflector)

#### Introduction

`contiv-ksr` subscribes to K8s, watches for state changes of specific
resources (currently: namespaces, pods, policies) and propagates
received updates into the ETCD datastore as protobuf-formatted key-value
data. `contiv-agent` watches and reads these K8s state data from ETCD
primarily in order to configure network policies between pods.

#### Protocol

State data of k8s resources are stored into the data store in a protobuf
format. Each resource type has its own data model and a key prefix under
which the formatted data are stored:
  * Namespace:
    * [data model](../../plugins/ksr/model/namespace/namespace.proto)
    * key: `/vnf-agent/contiv-ksr/k8s/namespace/{namespace-name}`
  * Pod:
    * [data model](../../plugins/ksr/model/pod/pod.proto)
    * key: `/vnf-agent/contiv-ksr/k8s/namespace/{namespace-name}/pod/{pod-name}`
  * Network Policy:
    * [data model](../../plugins/ksr/model/policy/policy.proto)
    * key: `/vnf-agent/contiv-ksr/k8s/namespace/{namespace-name}/policy/{policy-name}`

#### Configuration

The location of the ETCD configuration file is defined either
with the `--etcdv3-config` argument or through the `ETCDV3_CONFIG`
environment variable. The attached example configuration file `etcdv3.conf`
(used by default if PWD is this directory) assumes that ETCD listens
on the localhost, port `22379` for client communication.

Additionally, `contiv-ksr` reads kubeconfig to get the access credentials
and the address of the K8s cluster that it should connect to.
The location of kubeconfig is specified either with the `--kube-config`
argument or through the `KSR_CONFIG` environment variable.
If not specified, `contiv-ksr` will grab the default admin credentials
from: `/etc/kubernetes/admin.conf`.

Additionally, `contiv-ksr` exposes REST API for a remote management.
Currently, only loggers can be configured remotely:
  * list all registered loggers:
    ```
    curl -X GET http://<host>:<port>/log/list
    ```
  * set log level for a registered logger:
    ```
    curl -X PUT http://<host>:<port>/log/<logger-name>/<log-level>
    ```

By default, the REST API is attached to the port `9191`, but the address
can be changed in the configuration file passed with the `--http-config`
CLI option (or through `HTTP_CONFIG` env. variable), see attached
`http.conf`.

The interesting loggers for `contiv-ksr` are:
  * `ksr-namespace`: log messages associated with processing of changes
                     in k8s namespaces
  * `ksr-policy`: log messages associated with processing of changes
                  in k8s policies
  * `ksr-pod`: log messages associated with processing of changes
               in k8s pods

#### Requirements

To start `contiv-ksr` you have to have Kubernetes and (a separate) ETCD
running first.

`kubeadm` can be used to easily and quickly install a Kubernetes cluster,
see: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/

ETCD deployed by kubeadm does not accept remote connections,
therefore you need to start a new instance and attach it to a different
port (choose port number `22379` to match with the attached example
configuration).

If you don't have ETCD installed locally, you can use the following
docker image:
```
sudo docker run -p 22379:2379 --name etcd --rm \
    quay.io/coreos/etcd:v3.0.16 /usr/local/bin/etcd \
    -advertise-client-urls http://0.0.0.0:2379 \
    -listen-client-urls http://0.0.0.0:2379
```

#### Usage

Start `contiv-ksr` with:
```
./contiv-ksr [--etcdv3-config <config-filepath>] \
             [--http-config <config-filepath>] \
             [--kube-config <config-filepath>]
```
Run `contiv-ksr` with enough privileges to read the selected
configuration files. For example, kubeconfig `admin.conf` requires
superuser privileges.