# Contiv VPP

Deploy Contiv VPP networking

The deployment consists of the following components:
 * contiv-etcd - deployed on the master node
 * contiv-vswitch - deployed on each node
 * contiv-ksr - deployed on the master node

The `values.yaml` file contains the default values for the
contiv-vpp templates.

## Installing the chart

As with all helm installations, it requires tiller running in the cluster. Tiller is typically installed on clusters where networking is already setup, which can be a challenge for using this particular chart.

To install without tiller, you can generate the manifest from this chart and install via kubectl:

```console
helm template --name my-release ../contiv-vpp > manifest.yaml
kubectl apply -f manifest.yaml
```

To install with tiller, you will most likely need to modify the tiller manifest. The manifest can be optained with:

```console
helm init --dry-run --debug > tiller.yaml
```

Simply change it to a `kind: Daemonset` and remove the `strategy: {}` and `status: {}` lines to allow tiller to run in a cluster without a CNI:

```console
kubectl apply -f tiller.yaml
```

With tiller running in the cluster the chart can be installed with typical helm commands.

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release contiv-vpp
```
## Uninstalling the chart

```console
$ helm delete --purge my-release
```


## Configuration

The following tables lists the configurable parameters of the Contiv-VPP chart and their default values.

Parameter | Description | Default
--------- | ----------- | -------
`contiv.mtuSize` | MTU Size | 1500
`contiv.tcpStackDisabled` | Disable TCP stack | `True`
`contiv.useTAPInterfaces` | Enable TAP interfaces | `True`
`contiv.tapInterfaceVersion`| TAP interface version | 2
`contiv.stealInterface` | Enable Steal The NIC feature on the specified interface on each node | `""`
`contiv.stealFirstNIC` | Enable Steal The NIC feature on the first interface on each node | `False`
`contiv.natExternalTraffic`| NAT cluster-external traffic | `True`
`contiv.serviceLocalEndpointWeight` | load-balancing weight for locally deployed service endpoints | 1
`contiv.ipamConfig.podSubnetCIDR` | Pod subnet CIDR | `10.1.0.0/16`
`contiv.ipamConfig.podNetworkPrefixLen` | Pod network prefix length | `24`
`contiv.ipamConfig.PodIfIPCIDR` | Subnet CIDR for VPP-side POD addresses | `10.2.1.0/24`
`contiv.ipamConfig.vppHostSubnetCIDR` | VPP host subnet CIDR | `172.30.0.0/16`
`contiv.ipamConfig.vppHostNetworkPrefixLen` | VPP host network prefix length | `24`
`contiv.ipamConfig.vxlanCIDR` | VXLAN CIDR | `192.168.30.0/24`
`contiv.ipamConfig.nodeInterconnectCIDR` | Node interconnect CIDR, uses DHCP if empty | `""`
`contiv.ipamConfig.serviceCIDR` | Service CIDR | `""`
`contiv.nodeConfig.*` | List of node configs, see example section in values.yaml | `""`
`contiv.vswitch.defineMemoryLimits` | define limits for vswitch container | `false`
`contiv.vswitch.hugePages2miLimit` | limit of memory allocated by 2048Kb hugepages for vswitch container| `1024Mi`
`contiv.vswitch.memoryLimit` | memory limit for vswitch container | `1024Mi`
`cni.image.repository` | cni container image repository | `contivvpp/cni`
`cni.image.tag`| cni container image tag | `latest`
`cni.image.pullPolicy` | cni container image pull policy | `IfNotPresent`
`ksr.image.repository` | ksr container image repository | `contivvpp/ksr`
`ksr.image.tag`| ksr container image tag | `latest`
`ksr.image.pullPolicy` | ksr container image pull policy | `IfNotPresent`
`etcd.image.repository` | etcd container image repository | `quay.io/coreos/etcd`
`etcd.image.tag`| etcd container image tag | `latest`
`etcd.image.pullPolicy` | etcd container image pull policy | `IfNotPresent`
`etcd.usePersistentVolume` | Use Kubernetes persistent volume (when enabled, disables dataDir hostPath) | `False`
`etcd.persistentVolumeSize` | Size of Kubernetes persistent volume | `2Gi`
`etcd.persistentVolumeStorageClass` | Kubernetes persistent volume storage class (use "-" for an empty storage class) | (no value)
`etcd.dataDir` | Use hostPath of this directory to persist etcd data (ignored if usePersistentVolume is true) | `/var/etcd`
`etcd.service.nodePort` | Port to be used as the service NodePort | `32379`
`etcd.secureTransport` | Secure access to ETCD using SSL/TLS certificates | `false`
`etcd.secrets.mountFromHost` | If true, SSL/TLS certificates must be present in the mountDir on each host. If false, certificates must be present in the current directory, and will be distributed to each host via k8s secret feature | `true`
`etcd.secrets.mountDir` | Directory where certificates should be located, in case that mountFromHost is true | `/var/etcd/contiv-secrets`
`etcd.caCert` | Name of the file with certificate of the certification authority. | `ca.pem`
`etcd.serverCert` | Name of the file with certificate of the ETCD server. | `server.pem`
`etcd.serverKey` | Name of the file with private key of the ETCD server. | `server-key.pem`
`etcd.clientCert` | Name of the file with certificate of the ETCD client. | `client.pem`
`etcd.clientKey` | Name of the file with private key of the ETCD client. | `client-key.pem`
`govpp.healthCheckProbeInterval` | Health check proble interval (nanoseconds) | `1000000000`
`govpp.healthCheckReplyTimeout` | Health check reply timeout (nanoseconds) | `500000000`
`govpp.healthCheckThreshold` | Health check threshold | 3
`govpp.replyTimeout` | VPP binary API request timeout (nanoseconds) | 3000000000
`logs.defaultLevel` | Default level of logging | `debug`
