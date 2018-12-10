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

To install without tiller for arm64, you can generate the manifest from this chart and install via kubectl:

```console
helm template --name my-release ../contiv-vpp -f ./values-arm64.yaml,./values.yaml > manifest-arm64.yaml
kubectl apply -f manifest-arm64.yaml
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
`contiv.mtuSize` | MTU Size | 1450
`contiv.useTAPInterfaces` | Enable TAP interfaces | `True`
`contiv.tapInterfaceVersion`| TAP interface version | 2
`contiv.tapv2RxRingSize`| TAPv2 interface receive ring size | 256
`contiv.tapv2TxRingSize`| TAPv2 interface transmit ring size | 256
`contiv.vmxnet3RxRingSize`| Vmxnet3 interface receive ring size | 1024
`contiv.vmxnet3TxRingSize`| Vmxnet3 interface transmit ring size | 1024
`contiv.stealInterface` | Enable Steal The NIC feature on the specified interface on each node | `""`
`contiv.stealFirstNIC` | Enable Steal The NIC feature on the first interface on each node | `False`
`contiv.natExternalTraffic`| NAT cluster-external traffic | `True`
`contiv.scanIPNeighbors`| Periodically scan and probe IP neighbors to maintain the ARP table | `True`
`contiv.ipNeighborScanInterval`| IP neighbor scan interval in minutes | `1`
`contiv.ipNeighborStaleThreshold`| Threshold in minutes for neighbor deletion | `4`
`contiv.serviceLocalEndpointWeight` | load-balancing weight for locally deployed service endpoints | 1
`contiv.disableNATVirtualReassembly` | Disable NAT virtual reassembly (drop fragmented packets) | `False`
`contiv.ipamConfig.podSubnetCIDR` | Pod subnet CIDR | `10.1.0.0/16`
`contiv.ipamConfig.podSubnetOneNodePrefixLen` | Pod network prefix length | `24`
`contiv.ipamConfig.PodVPPSubnetCIDR` | Subnet CIDR for VPP-side POD addresses | `10.2.1.0/24`
`contiv.ipamConfig.vppHostSubnetCIDR` | VPP host subnet CIDR | `172.30.0.0/16`
`contiv.ipamConfig.vppHostSubnetOneNodePrefixLen` | VPP host network prefix length | `24`
`contiv.ipamConfig.vxlanCIDR` | VXLAN CIDR | `192.168.30.0/24`
`contiv.ipamConfig.nodeInterconnectCIDR` | Node interconnect CIDR, uses DHCP if empty | `""`
`contiv.ipamConfig.serviceCIDR` | Service CIDR | `""`
`contiv.nodeConfig.*` | List of node configs, see example section in values.yaml | `""`
`contiv.vswitch.defineMemoryLimits` | define limits for vswitch container | `false`
`contiv.vswitch.hugePages2miLimit` | limit of memory allocated by 2048Kb hugepages for vswitch container| `1024Mi`
`contiv.vswitch.hugePages1giLimit` | limit of memory allocated by 1Gb hugepages for vswitch container| `""`
`contiv.vswitch.memoryLimit` | memory limit for vswitch container | `1024Mi`
`contiv.vswitch.enableCoreDumps` | enable core dumps of VPP into coreDumpsDir | `false`
`contiv.vswitch.coreDumpsDir` | location of the VPP core dumps | `/var/contiv/dumps`
`controller.delayLocalResync` | how long to wait for etcd connection before using bolt DB as a fallback for startup resync | `5000000000`
`controller.enablePeriodicHealing` | enable periodic resync | `False`
`controller.periodicHealingInterval` | periodic resync time interval in nanoseconds | `30000000000`
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
`etcd.secrets.mountDir` | Directory where certificates should be located, in case that mountFromHost is true | `/var/contiv/etcd-secrets`
`etcd.caCert` | Name of the file with certificate of the certification authority. | `ca.pem`
`etcd.serverCert` | Name of the file with certificate of the ETCD server. | `server.pem`
`etcd.serverKey` | Name of the file with private key of the ETCD server. | `server-key.pem`
`etcd.clientCert` | Name of the file with certificate of the ETCD client. | `client.pem`
`etcd.clientKey` | Name of the file with private key of the ETCD client. | `client-key.pem`
`etcd.cipherSuites` | Supported TLS cipher suite for ETCD | AES128 SHA256/384
`govpp.healthCheckProbeInterval` | Health check proble interval (nanoseconds) | `1000000000`
`govpp.healthCheckReplyTimeout` | Health check reply timeout (nanoseconds) | `500000000`
`govpp.healthCheckThreshold` | Health check threshold | 3
`govpp.replyTimeout` | VPP binary API request timeout (nanoseconds) | 3000000000
`logs.defaultLevel` | Default level of logging | `debug`
`http.enableBasicAuth` | Enable basic auth for REST endpoints | `false`
`http.enableServerCert` | Enable HTTPS for REST endpoints | ` false`
`http.mountFromHost` | If true, SSL/TLS certificates must be present in the mountDir on each host. If false, certificates must be present in the current directory, and will be distributed to each host via k8s secret feature| `false`
`http.mountDir` | Directory where certificates should be located on all nodes, in case that mountFromHost is true |`/var/certs`
`http.serverCert` | Name of the file with certificate of the HTTP server | `server.crt`
`http.serverKey` | Name of the file with private key of the HTTP server |`server.key`
`http.basicAuth` | credentials to be used by basic-auth, format <username>:<password>| `user:pass`
`telemetry.pollingInterval` | Default polling interval for telemetry plugin (nanoseconds) | `30000000000`
`telemetry.disabled` | Disables the telemetry plugin | `true`
`bolt.usePersistentVolume` | Use Kubernetes persistent volume (when enabled, disables dataDir hostPath) | `False`
`bolt.persistentVolumeSize` | Size of Kubernetes persistent volume | `2Gi`
`bolt.persistentVolumeStorageClass` | Kubernetes persistent volume storage class (use "-" for an empty storage class) | (no value)
`bolt.dataDir` | Use hostPath of this directory to persist bolt data (ignored if usePersistentVolume is true) | `/var/bolt`
