### Setting up a node with a single NIC


#### Installing the STN daemon
The STN Daemon must be installed on every node in the cluster that has only 
one NIC. The STN daemon installation(*) should be performed before deployment 
of the Contiv-VPP plugin.

\* Docker daemon must be present when installing STN.  Also, Docker must be configured to allow shared mount.
On CentOS, this may not be the case by default.  You can enable it by following the instructions at
https://docs.portworx.com/knowledgebase/shared-mount-propogation.html.

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```
The install script should output the following:
```
Installing Contiv STN daemon.
Starting contiv-stn Docker container:
550334308f85f05b2690f5cfb5dd945bd9c501ab9d074231f15c14d7098ef212
```

Check that the STN daemon is running:
```
docker ps -a 
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
550334308f85        contivvpp/stn       "/stn"              33 seconds ago      Up 33 seconds                           contiv-stn
```

Check that the STN daemon is operational:
```
docker logs contiv-stn
```
The expected logs would look like the following excerpt:
```
2018/02/23 10:08:34 Starting the STN GRPC server at port 50051
```

For more details, please read the Go documentation for [contiv-stn](../../cmd/contiv-stn/doc.go)
and [contiv-init](../../cmd/contiv-init/doc.go).


#### Creating VPP configuration
Create the VPP configuration for the hardware interface as described 
[here](https://github.com/contiv/vpp/blob/master/docs/VPP_CONFIG.md#single-nic-configuration).


#### Configuring STN in Contiv-VPP K8s deployment files
The STN feature is disabled by default. It needs to be enabled either globally,
or individually for every node in the cluster.

This can be either done by modification of the deployment YAML file (we use this approach in this guide), 
or using [helm and corresponding helm options](../../k8s/contiv-vpp/README.md).


##### Global configuration:
Global configuration is used in homogeneous environments where all nodes in 
a given cluster have the same hardware configuration, for example only a single
Network Adapter. To enable the STN feature globally, put the `stealFirstNIC: True`
stanza into the [`contiv.conf`][1] deployment file, for example:
```
data:
  contiv.conf: |-
    ...
    stealFirstNIC: True
    ...
```

Setting `StealFirstNIC` to `True` will tell the STN Daemon on every node in the 
cluster to steal the first NIC from the kernel and assign it to VPP. Note that
the Network Adapters on different nodes do not need to be of the same type. You
still need to create the respective vswitch configurations on every node in the
cluster, as shown [above](#creating-vpp-configuration).


##### Individual configuration:
Individual configuration is used in heterogeneous environments where each node
in a given cluster may be configured differently. The configuration of nodes can
be defined in two ways:

- **contiv deployment file** This approach expects configuration for all cluster nodes
to be part of contiv deployment yaml file. To enable the STN feature for a specific
node in the cluster, put the following stanza into its Node Configuration in the [`contiv.conf`][1]
deployment file, for example:
```
...
    nodeConfig:
    - nodeName: "k8s-master"
      stealInterface: "enp0s8"
    - nodeName: "k8s-worker1"
      stealInterface: "enp0s8"
...
``` 

- **CRD** The node configuration is applied using custom defined k8s resource. The same behavior
as above can be achieved by the following CRD config. Usage of CRD allows to dynamically add new configuration 
for nodes joining a cluster.

```
$ cat master.yaml

# Configuration for node in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-master
spec:
  stealInterface: "enp0s8"

$ cat worker1.yaml

# Configuration for node in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-worker1
spec:
  stealInterface: "enp0s8"


kubectl apply -f master.yaml
kubectl apply -f worker1.yaml
```

These two ways of configuration are mutually exclusive. You select the one you want to use by
`crdNodeConfigurationDisabled` option in `contiv.conf`.

Note that regardless of node config option you still have to create the vswitch configuration on the node as
shown [here](#creating-vpp-configuration).


#### Uninstalling the STN daemon

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh) --uninstall
```
The install script should output the following:
```
Uninstalling Contiv STN daemon.
Stopping contiv-stn Docker container:
contiv-stn
```
Make sure that the STN daemon has been uninstalled:
```
docker ps -q -f name=contiv-stn
```
No containers should be listed.

[1]: ../../k8s/contiv-vpp.yaml
