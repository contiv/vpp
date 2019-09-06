# Contiv-VPP Helm Installation

This folder contains Contiv-VPP deployment helm chart files:

* the chart template is located in [`templates/vpp.yaml`](templates/vpp.yaml)
* the default values for the template is located in  [`values.yaml`](values.yaml)


## Installing the chart

As with all helm installations, it requires tiller running in the cluster. Tiller is typically installed on 
clusters where networking is already setup, which can be a challenge for using this particular chart.

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

To install with tiller, you will most likely need to modify the tiller manifest. The manifest can be obtained with:

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
Some of them are described in more detail in [contiv.conf README](../README.md#contivconf).

Parameter | Description | Default
--------- | ----------- | -------
`contiv.nodeToNodeTransport` | Transportation used for node-to-node communication | `vxlan`
`contiv.useSRv6ForServices` | Enable usage of SRv6 for k8s service | `false`
`contiv.useSRv6ForServiceFunctionChaining` | Enable use SRv6(IPv6) for Service Function Chaining in k8s service | `false`
`contiv.useDX6ForSrv6NodetoNodeTransport` | Enable usage of DX6 instead of DT6 for node-to-node communication (only for pod-to-pod case with full IPv6 environment) | `false`
`contiv.mtuSize` | MTU Size | 1450
`contiv.useTAPInterfaces` | Enable TAP interfaces | `True`
`contiv.tapInterfaceVersion`| TAP interface version | 2
`contiv.tapv2RxRingSize`| TAPv2 interface receive ring size | 256
`contiv.tapv2TxRingSize`| TAPv2 interface transmit ring size | 256
`contiv.enableGSO`| Enable Generic Segmentation Offload on TAP interfaces  | `True`
`contiv.vmxnet3RxRingSize`| Vmxnet3 interface receive ring size | 1024
`contiv.vmxnet3TxRingSize`| Vmxnet3 interface transmit ring size | 1024
`contiv.interfaceRxMode`| Interface packet receive mode: "" == "default" / "polling" / "interrupt" / "adaptive"  | `"default"`
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
`contiv.ipamConfig.vppHostSubnetCIDR` | VPP host subnet CIDR | `172.30.0.0/16`
`contiv.ipamConfig.vppHostSubnetOneNodePrefixLen` | VPP host network prefix length | `24`
`contiv.ipamConfig.vxlanCIDR` | VXLAN CIDR | `192.168.30.0/24`
`contiv.ipamConfig.nodeInterconnectCIDR` | Node interconnect CIDR, uses DHCP if empty | `""`
`contiv.ipamConfig.serviceCIDR` | Service CIDR | `""`
`contiv.ipamConfig.defaultGateway` | Default gateway for all nodes (can be overridden by a nodeconfig)| `""`
`contiv.ipamConfig.srv6.servicePolicyBSIDSubnetCIDR` | Subnet applied to lowest k8s service IP to get unique (per service,per node) binding sid for SRv6 policy | `8fff::/16`
`contiv.ipamConfig.srv6.servicePodLocalSIDSubnetCIDR` | Subnet applied to k8s service local pod backend IP to get unique sid for SRv6 Localsid referring to local pod beckend using DX6 end function | `9300::/16`
`contiv.ipamConfig.srv6.serviceHostLocalSIDSubnetCIDR` | Subnet applied to k8s service host pod backend IP to get unique sid for SRv6 Localsid referring to local host beckend using DX6 end function | `9300::/16`
`contiv.ipamConfig.srv6.serviceNodeLocalSIDSubnetCIDR` | Subnet applied to node IP to get unique sid for SRv6 Localsid that is intermediate segment routing to other nodes in Srv6 segment list (used in k8s services) | `9000::/16`
`contiv.ipamConfig.srv6.nodeToNodePodLocalSIDSubnetCIDR` | Subnet applied to node IP to get unique sid for SRv6 Localsid that is the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into pod VRF table (DT6 end function of localsid) | `9501::/16`
`contiv.ipamConfig.srv6.nodeToNodeHostLocalSIDSubnetCIDR` | Subnet applied to node IP to get unique sid for SRv6 Localsid that is the only segment in node-to-node Srv6 tunnel. Traffic from tunnel continues routing by looking into main VRF table (DT6 end function of localsid) | `9500::/16`
`contiv.ipamConfig.srv6.nodeToNodePodPolicySIDSubnetCIDR` | Subnet applied to node IP to get unique bsid for SRv6 policy that defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodePodLocalSIDSubnetCIDR` | `8501::/16`
`contiv.ipamConfig.srv6.nodeToNodeHostPolicySIDSubnetCIDR` | Subnet applied to node IP to get unique bsid for SRv6 policy that defines path in node-to-node Srv6 tunnel as mentioned in `srv6NodeToNodeHostLocalSIDSubnetCIDR`. | `8500::/16`
`contiv.ipamConfig.srv6.sfcPolicyBSIDSubnetCIDR` | Subnet applied to SFC ID(trimmed hash of SFC name) to get unique binding sid for SRv6 policy used in SFC | `8eee::/16`
`contiv.ipamConfig.srv6.sfcServiceFunctionSIDSubnetCIDR` | Subnet applied to combination of SFC ID(trimmed hash of SFC name) and service function pod IP address to get unique sid for SRv6 Localsid referring to SFC service function | `9600::/16`
`contiv.ipamConfig.srv6.sfcEndLocalSIDSubnetCIDR` | Subnet applied to the IP address of last link of SFC to get unique sid for last localsid in the segment routing path representing SFC chain | `9310::/16`
`contiv.ipamConfig.srv6.sfcIDLengthUsedInSidForServiceFunction` | Length(in bits) of SFC ID(trimmed hash of SFC name) that should be used by computing SFC ServiceFunction localsid SID. A hash is computed from SFC name, trimmed by length (this setting) and used in computation of SFC ServiceFunction localsid SID (SID=prefix from sfcServiceFunctionSIDSubnetCIDR + trimmed hash of SFC name + service function pod IP address). | `16`
`contiv.nodeConfig.*` | List of node configs, see example section in values.yaml | `""`
`contiv.vswitch.useSocketVPPConnection` | use unix domain socket for connection to VPP | `false`
`contiv.vswitch.defineMemoryLimits` | define memory requests & limits for vswitch container | `true`
`contiv.vswitch.hugePages2miLimit` | request & limit of memory allocated by 2048Kb hugepages for vswitch container| `512Mi`
`contiv.vswitch.hugePages1giLimit` | request & limit of memory allocated by 1Gb hugepages for vswitch container| `""`
`contiv.vswitch.memoryLimit` | overall memory limit for vswitch container | `512Mi`
`contiv.vswitch.enableCoreDumps` | enable core dumps of VPP into coreDumpsDir | `false`
`contiv.vswitch.coreDumpsDir` | location of the VPP core dumps | `/var/contiv/dumps`
`controller.enableRetry` | Enable retry of failed CRUD operations | `true`
`controller.delayRetry` | Delay retry of failed CRUD operations by the given time interval in nanoseconds | `1000000000`
`controller.maxRetryAttempts` | Maximum number of retries to be performed for failed CRUD operations | `3`
`controller.enableExpBackoffRetry` | Every next retry of failed CRUD operations is delayed by twice as long time interval as the previous one | `true`
`controller.delayLocalResync` | How long to wait for etcd connection before using bolt DB as a fallback for startup resync | `5000000000`
`controller.startupResyncDeadline` | Deadline for the first resync to execute (in nanoseconds after startup) until the agent is restarted | `30000000000`
`controller.enablePeriodicHealing` | Enable periodic resync | `False`
`controller.periodicHealingInterval` | Periodic resync time interval in nanoseconds | `30000000000`
`controller.delayAfterErrorHealing` | How much to delay healing resync after a failure (in nanoseconds) | `5000000000`
`controller.remoteDBProbingInterval` | Time interval between probes triggered to test connectivity with the remote DB (in nanoseconds) | `3000000000`
`controller.recordEventHistory` | enable recording of processed events | `True`
`controller.eventHistoryAgeLimit` | event records older than the given age limit (in minutes) are periodically trimmed from the history | `1440`
`controller.permanentlyRecordedInitPeriod` | time period (in minutes) from the start of the application with events permanently recorded | `60`
`cni.image.repository` | cni container image repository | `contivvpp/cni`
`cni.image.tag`| cni container image tag | `latest`
`cni.image.pullPolicy` | cni container image pull policy | `IfNotPresent`
`ksr.image.repository` | ksr container image repository | `contivvpp/ksr`
`ksr.image.tag`| ksr container image tag | `latest`
`ksr.image.pullPolicy` | ksr container image pull policy | `IfNotPresent`
`etcd.useExternalInstance` | do not deploy etcd as a part of contiv, options except `externalInstance` block are ignored if set to `true` | `false`
`etcd.externalInstance.secretName` | name of secret containing etcd certificates | `false`
`etcd.externalInstance.endpoints` | endpoints of external etcd instance | `false`
`etcd.image.repository` | etcd container image repository | `quay.io/coreos/etcd`
`etcd.image.tag`| etcd container image tag | `latest`
`etcd.image.pullPolicy` | etcd container image pull policy | `IfNotPresent`
`etcd.usePersistentVolume` | Use Kubernetes persistent volume (when enabled, disables dataDir hostPath) | `False`
`etcd.persistentVolumeSize` | Size of Kubernetes persistent volume | `2Gi`
`etcd.persistentVolumeStorageClass` | Kubernetes persistent volume storage class (use "-" for an empty storage class) | (no value)
`etcd.dataDir` | Use hostPath of this directory to persist etcd data (ignored if usePersistentVolume is true) | `/var/etcd`
`etcd.service.nodePort` | Port to be used as the service NodePort | `32379`
`etcd.service.useNodeIP` | If true nodeIP is used to access service, nodeIP otherwise | `true`
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
`crd.validateInterval` | Interval in minutes between Contiv configuration validations for TelemetryReport CRD | `1`
`crd.validateState` | Which state of the Contiv configuration to validate for TelemetryReport CRD (options: "SB", "internal", "NB") | `SB`
`crd.disableNetctlREST` | Disable exposing of contiv-netctl via REST | `false`
