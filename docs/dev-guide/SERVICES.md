# Kubernetes services in Contiv/VPP

## Overview

Service is a Kubernetes abstraction providing a convenient single entry point
of access to a group of pods. In other words, a service can be thought of
as a dynamic loadbalancer for a set of pods (and the containers living inside
them), automatically managed by the K8s framework itself. The set of Pods
targeted by a Service is (usually) determined by a Label Selector. This label
query frequently matches pods created by one or more replication controllers.

Services provide important features that are standardized across the cluster:
 * Load-balancing
 * Service discovery between applications
 * Support for zero-downtime application deployments

A Service in Kubernetes is a REST object, similar to a Pod. Like all of the REST
objects, a Service definition can be POSTed to the apiserver to create a new
instance of the service. Additionally, for Kubernetes-native applications,
Kubernetes offers a simple Endpoints API for updating the service whenever
the set of Pods in a service changes. For services without label selectors
the associated endpoint object can also be edited manually through the REST
interface, giving the user full control over the set of endpoints assigned
to a service.

A Kubernetes service can be published to the cluster and to the outside world in
various ways:
 * `ClusterIP`: exposing the service on a cluster-internal IP
 * `NodePort`: exposing the service on every node’s host stack IP at a static
   port from a pre-determined range (default: 30000-32767),
 * `externalIPs`: an unlimited number of cluster-outside IP addresses that should
   be routed to one or more cluster nodes, where they get load-balanced across
   endpoints by Kubernetes.

Furthermore, every service defined in the cluster (including the DNS server
itself) is assigned a DNS name `<service-name.service.namespace>`. By default,
every pod’s DNS search list will include the pod’s own namespace and the cluster’s
default domain.

Contiv/VPP implements Kubernetes services in the full scope of the specification
for the IP protocol version 4.

## Kube-proxy

The [Kubernetes network proxy][kube-proxy] is a Kubernetes component running on
every node. It reflects services and endpoints as defined in the Kubernetes API
and can do simple TCP and UDP stream forwarding or round robin TCP/UDP
load-balancing across a set of backends using iptables or [IPVS (IP Virtual Server)][ipvs].

While other CNI plugin providers rely heavily on kube-proxy for their services
implementations, in Contiv/VPP Kube proxy plays a secondary role. For the most
part, load-balancing and translations between services and endpoints are done
**inside VPP** using the high performance [VPP-NAT plugin](#the-vpp-nat-plugin).
The only exception is traffic initiated from the host stack on one of the cluster
nodes - whether it is a pod with host networking, an application running
directly on the host (outside of all containers), or an external application
accessing a service through the host stack (e.g. in the 2-NIC use case). Clients
accessing services from within pods connected to VPP or from the outside of the
cluster through the primary VPP GigE interface always bypass Kube-proxy.

## The VPP-NAT plugin

[VPP-NAT plugin][vpp-nat-plugin] is an implementation of NAT44 and NAT64 for VPP.
The target use case is a general IPv4 CPE NAT, a CGN and to act as a NAT44
in a Openstack deployment. It is intended to be pluggable, in the sense that
it should be possible to plug the NAT44 function together with the MAP-E IPv4
to IPv6 translator to create a MAP-E CE, likewise one can plug the NAT44
together with MAP-T to create a MAP-T CE or 464XLAT.

In Contiv-VPP the VPP-NAT plugin is used in the data-plane to:
 1. Load-balance and forward *IPv4* traffic between services and endpoints,
    i.e. **1-to-many NAT**,
 2. **Dynamically source-NAT** node-outbound *IPv4* traffic to enable Internet
    access for pods with private addresses.

The following subsection describes key VPP-NAT configuration items, focusing
on features used in the Contiv-VPP data plane. Certain aspects of the VPP-NAT
configuration are explained in a greater detail as they play a pivotal role
in the implementation of Kubernetes services in Contiv-VPP.

### Configuration
#### Interface features
Traffic flowing through an interface won't be NATed unless the VPP-NAT plugin
is informed whether the interface connects VPP with an internal (`in`) or
an external network (`out`). For a given connection, the network types of
ingress and egress interfaces determine the direction in which the NAT should
be applied.

CLI example:
```
vpp# set interface nat44 out GigabitEthernet0/a/0
vpp# set interface nat44 in tap1
```

#### 1-to-many NAT
1-to-many NAT is a collection of **static mappings**, where each mapping
consists of one **external** IP:port endpoint and multiple weighted **local**
endpoints. For example, expressed as a VPP CLI command, a 1-to-many NAT static
mapping looks as follows:
```
vpp# nat44 add load-balancing static mapping protocol tcp
           external 1.2.3.4:80 local 10.100.10.10:8080 probability 80 local 10.100.10.20:8080 probability 20
```
The type declaration for static mappings can be found in the [NAT plugin BIN-API][vpp-nat-plugin-api],
request `nat44_add_del_lb_static_mapping`:
```
typeonly define nat44_lb_addr_port {
 u8 addr[4];
 u16 port;
 u8 probability;
};

define nat44_add_del_lb_static_mapping {
 ...
 u8 external_addr[4];
 u16 external_port;
 u8 protocol;
 u32 vrf_id;
 u8 twice_nat;
 u8 self_twice_nat;
 u8 out2in_only;
 u8 tag[64];
 u8 local_num;
 vl_api_nat44_lb_addr_port_t locals[local_num];
};
```
The fields in the above structure are as follows:
 * `nat44_lb_addr_port.addr`: IPv4 address of a local endpoint.
 * `nat44_lb_addr_port.port`: L4 port number of a local endpoint.
 * `nat44_lb_addr_port.probability`: probability (weight) of the local endpoint
   to be randomly matched.
 * `external_addr`: external IPv4 address of the service.
 * `external_port`: external L4 port number of the service.
 * `protocol`: IP protocol number of the service (UDP or TCP).
 * `vrf_id`: internal network VRF ID.
 * `twice_nat`: translate both the source and destination address with a single
   rule. Twice NAT is not used in Contiv-VPP - source-NAT is not applied for
   intra-node traffic.
 * `self-twice-nat`: a special feature added for Contiv to enable access
   to service from one of its own endpoints (i.e. access from itself). If you hit
   the same endpoint as the request originated from, then the source and
   destination IPs are equal after DNAT translation. This is an issue because
   the response will not be routed back through the VPP, where it would be SNATed
   back to the service IP, but instead it will get delivered locally, causing
   a mismatch between request and response in terms of src/dst IP addresses.
   So in case the source and destination IPs are equal after DNAT, self-twice-nat
   tells the NAT plugin to also translate the source with a selected IP address
   that is routed from each pod through TAP back into VPP. We choose the last
   unicast IP address from `PodCIDR` to server as this virtual loopback and
   ensure that it is never allocated to a pod.
 * `out2in-only`: if enabled the NAT plugin will apply the associated static
   mapping and create a new dynamic entry for a session only if the
   destination == mappings‘ external IP (as DNAT). Under the default configuration,
   the mapping would apply (as source NAT) also for connections initiated from
   the local IPs, replacing the source address with the external IP (breaking
   policies for example).
 * `tag`: string tag opaque to VPP-NAT plugin. Used by Contiv-VPP control plane
   to associate NAT rule with the corresponding service, which is needed by the
   re-sync procedure.
 * `local_num`: the number of local endpoints.
 * `locals`: list of local endpoints.

#### Dynamic source-NAT
For a dynamic SNAT of the outbound traffic, the interface needs to be further
put into the post-routing mode.  e.g.:
```
vpp# set interface nat44 out GigabitEthernet0/a/0 output-feature
```

Dynamic NAT also requires a non-empty pool of IP address to choose from for
translations. Using a VPP CLI command, this would be configured as follows:
```
vpp# nat44 add address 1.2.3.4
```

#### Identity mappings
In Contiv/VPP we also use of **identity mappings**. An identity mapping is a
static NAT mappings that lets a real addresses to be translated to itself,
essentially bypassing NAT.

See [Mapping of services to VPP-NAT configurations](#mapping-of-services-to-vpp-nat-configurations)
to learn how we map the state of Kubernetes services into VPP-NAT configuration.

### VPP-NAT plugin limitations

The VPP-NAT plugin is a relatively recent addition to the VPP toolbox, and some
of its limitations impact Contiv-VPP. They are:
 1. Tracking of TCP sessions is experimental and has not been fully tested
 2. Not all dynamically created sessions are automatically cleaned up

## Services implementation in Contiv-VPP control plane
### VPP-NAT support in the Ligato VPP Agent

The VPP-NAT plugin for IPv4 is configured through the [nat-plugin][vpp-agent-nat-plugin]
in the [Ligato VPP Agent][ligato-vpp-agent]. The plugin receives a declarative
description of the desired NAT configuration on its northbound API, translates it
into a sequence of [VPP-NAT binary API][vpp-nat-plugin-api] calls, which are then
sent to GoVPP on the plugin's southbound API. These two levels of the NAT
configuration are being kept in sync even during VPP and agent restarts.

On the plugin's northbound API the NAT is modeled using a [proto file][nat-model]
definition. The northbound API model consists of two parts:
 1. Global configuration that allocates IPs for NAT address pools and marks
    interfaces to differentiate between internal and external networks attached
    to VPP
 2. List of labeled destination-NAT instances, each with a set of static
    and/or identity mappings

### Mapping of services to VPP-NAT configurations (IPv4)

In Contiv/VPP, a service is implemented as a set of VPP-NAT static mappings,
one for every external address. Static mappings of a single service are grouped
together and exported as a single instance of the [DNAT model][nat-model]
(destination NAT) for the [Ligato VPP Agent][ligato-vpp-agent] to configure.
Every DNAT instance is assigned a unique name consisting of the service name
and prefixed with the service namespace.

The translation of Kubernetes service definition into the corresponding set
of static mappings can be described by the following pseudo-code:
```
ServiceToDNAT:
    input: Kubernetes service definition; LocalEndpointWeight (Remote = 1; by default both equal)
    output: DNAT configuration for ligato/vpp-agent

    localEndpoints = {}

    serviceDNAT = {Name: service.namespace + "/" + service.name, StaticMappings: []}

    for every endpoint (IP:Port) of the service:
        add endpoint into <localEndpoints>
            with probability <LocalEndpointWeight> if locally deployed, 1 otherwise

    if service is NodePort:
        let serviceNodePort be the port allocated for the service on every node

        for every node in the cluster:
            for nodeIP in {nodeMgmtIP, nodeClusterIP}:
                add mapping {External-IP: <nodeIP>, External-Port: <serviceNodePort>, Locals: <localEndpoints>}
                    into <serviceDNAT.StaticMappings>

    if service has ClusterIP:
        let serviceClusterIP, serviceClusterPort be the assigned cluster-internal IP:port address

        add mapping {External-IP: <serviceClusterIP>, External-Port: <serviceClusterPort>, Locals: <localEndpoints>}
            into <serviceDNAT.StaticMappings>

    if service has ExternalIPs:
        for every serviceExternalIP, serviceExternalPort:

            add mapping {External-IP: <serviceExternalIP>, External-Port: <serviceExternalPort>, Locals: <localEndpoints>}
                into <serviceDNAT.StaticMappings>

    return serviceDNAT
```
Note that every node in the cluster will have the same set of static mappings
configured, only their respective probabilities may differ.

All mappings are configured with `out2in-only` and `self-twice-nat` enabled.
The latter further requires to specify the IP address of a virtual loopback,
used to route traffic between clients and services via VPP even if the source
and the destination are the same endpoint that would otherwise deliver
packets locally. [IPAM plugin][ipam-plugin] exposes the IP address
available for the NAT loopback via the API `NatLoopbackIP()`. It returns
the last unicast IP address from the range allocated for locally deployed pods.
This address is routed into VPP from every local pod, but IPAM ensures that it
never gets assigned to any real interface. The virtual loopback IP is added to
`TwiceNAT` address pool (extra source NAT for DNAT mappings) in the global NAT
configuration of the [Ligato VPP Agent][ligato-vpp-agent].

Next we need to mark interfaces with `in` & `out` features so that the VPP-NAT
plugin can determine the direction in which the NAT should be applied:

 1. `out` - denotes interfaces through which clients can access the service:
    this is effectively all interfaces - service can be accessed from the host
    (`tap0`), from pods (TAPs), other nodes (`loop0` for BD with VXLANs),
    from outside of the cluster (`GigE`-s) and even from its own endpoints
    (TAPs)

 2. `in` - denotes interfaces connecting service endpoints with VPP: every pod
    that acts as an endpoint of one or more services has to have its TAP
    interface marked as `in`

Lastly, we mark the `GigE` interface that connects VPP to the default gateway
as `output` and add the Node IP into the NAT main address pool. This enables
the dynamic source NAT in the post-routing phase for all the packets leaving
the node towards Internet. It is not desired to source-NAT packets sent
internally between cluster nodes, though. VXLAN encapsulated traffic therefore
needs to be excluded from NAT using an identity mapping, installed as a separate
DNAT instance, see [the next section](#integration-of-services-with-policies)
for more details.

### Integration of services with policies

K8s network policies run below services in the sense that they are defined
to be applied against real pod IP addresses and not against virtual service
IP addresses. This implies that the destination address translation for services
must execute **before** ACLs are applied. Conversely, any ACLs must be applied
before the node outbound traffic is source NAT-ed with the node IP.

VPP guarantees the following ordering between ACL and NAT44 nodes:
 1. acl-plugin-in-ip4-fa = ingress ACL
 2. ip4_snat_out2in = destination NAT
 3. routing / switching
 4. acl-plugin-out-ip4-fa = egress ACL
 5. ip4_snat_in2out_output = dynamic SNAT

More information on VPP node ordering can be found in the [Packet Flow guide][packet-flow-dev-guide].

As a consequence, with services in the equation the **ingress ACLs are not
eligible for the policy implementation**. Study [Development guide for policies][policies-dev-guide]
to learn how we can combine ingress and egress policies and end up with
semantically equivalent egress-only ACLs.

Furthermore, our implementation of policies assumes that the cluster **inter-node
traffic is sent with source IP addresses unchanged**. Because the inter-node
traffic uses VXLAN encapsulations, we only need to define identity mapping for
the VXLAN UDP port (4789) to make sure it's excluded from the source NAT.

Another minor instance where services and policies collide is with the virtual
NAT loopback used to route traffic between services and their own endpoints via
VPP. Every pod should be able to talk to itself, regardless of the policies
assigned. This means that the virtual loopback IP requires a special place
in the ACLs: Policy Configurator gives every pod with a non-empty policy
configuration the same rule permitting all traffic originating from the loopback.

### HostPort

Very similar to `NodePort` service is a feature called `HostPort` - it allows
to expose pod's internal port on the host IP and a selected host port number.
For example:
```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host
spec:
  containers:
  - image: nginx
    imagePullPolicy: IfNotPresent
    name: nginx-host
    ports:
    - containerPort: 8080
      hostPort: 80
  restartPolicy: Always
```
This feature is deprecated, however, as it limits the number of locations
where the Pod can be scheduled - the host port is statically set to a fixed
value, which automatically excludes all nodes where the same port is already
in use as there would be a port collision otherwise.

Still the feature is supported by Contiv/VPP, as it required no extra effort
to get it supported. The CNI (Container Network Interface) already ships with
[Port-mapping plugin][portmap-plugin], implementing redirection between host
ports and container ports using iptables. We only had to enable the plugin
in the [CNI configuration file for Contiv/VPP][contiv-cni-conflist].
Since the forwarding occurs in the realm of iptables on the host stack,
you will not get the same performance benefits as with `VPP-NAT`-based
redirection for NodePorts and other service types. Another limitation is that
in the 2-NIC solution the host port is exposed only with the IP address
assigned to the host and not on the GigE grabbed by VPP. With single NIC,
the STN plugin finds no listeners for host ports, thus forwarding the traffic
to the host stack, which then returns redirected packets back to VPP for final
delivery.

### Service Plugin

The mapping of Kubernetes services to the VPP-NAT configuration is implemented
by the [service plugin][service-plugin] using a **data-flow** based approach.
The plugin and the components it interacts with are split into multiple layers,
stacked on top of each other, with data moving from the top layer to the bottom
layer. Each layer receives service-related data from the layer above, processes
and/or transforms the received data and sends it to the layer below. On the top
of the stack is are K8s state data for endpoints and services as reflected into
Etcd by KSR. With each layer the abstraction level decreases until at the very
bottom of the stack a set of NAT rules is calculated and installed into the VPP
by the Ligato/vpp-agent.

The Service plugin consists of two components: the Policy Processor that matches
service metadata with endpoints and the Renderer (NAT44 or SRv6) that maps service
data received from the Processor into configuration ( [protobuf-modelled][nat-model] 
NAT44 or [protobuf-modelled][srv6-model] SRv6) for the Ligato/vpp-agent to install 
in the VPP.

The plugin, however, is not restricted to VPP-NAT/SRv6 based implementation
of Kubernetes services. The southbound of the processor is connected to
the northbound of the renderer(s) via a generic [renderer API][renderer-api].
The interface allows to have alternative and/or complementary Kubernetes service
implementations via one or multiple plugged renderers. For example, NAT44 handles
IPv4 protocol and SRv6 handles IPv6 protocol.Similarly, the set of supported 
vswitches in the data plane could be extended simply by adding new renderers 
for services and policies. Another use-case is to provide alternative 
implementation of Kubernetes services for the same stack - one being the default, 
others possibly experimental or tailor-made for specific applications. The set of 
renderers to be activated can be configurable or determined from the environment. 
Every active renderer is given the same set of data from the processor and it is 
up to them to split the input and produce a complementary output. Currently, 
the NAT44 Renderer(for IPv4) and SRv6 (for IPv6) are the only implementations 
of Renderer API shipped with the plugin.

The Renderer API defines server as an instance of `ContivService` - a structure
combining data from Service and Endpoint Kubernetes APIs into a minimalistic
representation. Furthermore, the API denotes interfaces connecting VPP
with external networks as `Frontends`, and those connecting VPP with service
endpoints as `Backends`. The classification of interfaces is VPP-specific and
may not be useful for future renderers.

![Service plugin layers][layers-diagram]

#### Skeleton

The [Service Plugin Skeleton][service-plugin-skeleton] implements the
[Ligato plugin API][cn-infra], which makes it pluggable with the Ligato
CN-Infra framework.

Inside the Service Plugin's `Init()` method both Processor and Renderer
are initialized and dependency injection is performed - at the very minimum,
every layer must depend on at least the layer below so that it can pass
transformed data further down the stack.

Additionally, the plugin itself is an [event handler][event-handler], registered
into the main [event loop][event-loop-guide] of the Contiv agent *after* the
[ipnet plugin][ipnet-plugin]. This ensures that connectivity between pods
and the VPP is established before any Renderer configuration is installed.

The Service plugin reads the state of 2 Kubernetes [resources][db-resources]
reflected into `etcd` by KSR and delegated to the plugin by resync and
`KubeStateChange` events: [services][svc-model] and [endpoints][eps-model].
Both services and endpoints need to be watched to learn the mapping between
service VIPs and the real pod IP addresses behind.
To keep the set of Frontend and Backend interfaces up-to-date, the plugins also
needs to react to `AddPod` & `DeletePod` events.
Lastly, `NodeUpdate` event is processed as well to determine and refresh the set
of all IP addresses in the cluster for NodePort services.

At the plugin skeleton layer, all the events of interest are just propagated
further into the Processor without any processing.

#### Processor

Processor receives and unpacks [update][processor-data-change] and
[resync][processor-data-resync] events. Service name and namespace is used
to match [service metadata][svc-model] with the associated [endpoints][eps-model].
The processor is also notified when locally deployed pod is created/updated or
deleted.

Additionally, the processor watches changes in the assignment of
cluster and management IPs for all nodes in the cluster, exposed by the
[nodesync plugin][nodesync-plugin] through `NodeUpdate` event.
Every time a new node is assigned an IP address or an existing one is destroyed,
the NodePort services have to be re-configured.

For each pod, the processor maintains a list of services that the pod acts
as an endpoint for. If pod matches label selector of at least one service,
it has to be regarded as Backend. Since any pod can be client of any service,
all running pods are always also regarded as Frontends.

Immediately after the resync, the set of Frontends also includes all GigE
interfaces, `tap0` interfaces that connect VPP to the host and the `loop0`
BVI interface in the BD where all VXLAN tunnels are terminated. A service may
have one or more endpoints deployed on another node, which makes `loop0` a
potential Backend. Likewise, `tap0` is an entry point for potential endpoints
in the host networking, thus we automatically mark it as Backend during resync.
The processor learns the names of all VPP interfaces from the [ipnet plugin][ipnet-plugin].

The processor outputs pre-processed service data to the layer below - renderers.
The [processor API][processor-api] allows to register one or more renderers
through `RegisterRenderer()` method. Currently, the NAT44 Renderer is the only
implemented and registered renderer.

#### NAT44 Renderer

The NAT44 Renderer maps `ContivService` instances into corresponding [DNAT model][nat-model]
instances that are then installed into VPP by the Ligato/vpp-agent. Frontends and
Backends are reflected as `in` & `out` interface features in the global NAT
configuration, updated every time a pod is created, destroyed, assigned to
a service for the first time, or no longer acting as a service endpoint.

NAT global configuration and DNAT instances generated in the Renderer are
appended to the [transaction][transaction-api] prepared for the given event by the
[Controller plugin] [controller-plugin]. The controller then commits the
transaction with NAT configuration (and potentially also with some more changes
from other plugins) into the [ligato/vpp-agent][ligato-vpp-agent] via the
[local client][local-client]. At the end of the pipe is [NAT plugin][vpp-agent-nat-plugin]
from the VPP-Agent, which applies NAT configuration into VPP through binary APIs.

To allow access from service to itself, the [IPAM plugin][ipam-plugin] is
asked to provide the virtual NAT loopback IP address, which is then inserted
into the `TwiceNAT` address pool. `self-twice-nat` feature is enabled for every
static mapping.

An extra feature of the renderer, outside the scope of services, is a management
of the dynamic source-NAT for node-outbound traffic, configured to enable
Internet access even for pods with private IPv4 addresses.
If dynamic SNAT is enabled in the Contiv configuration, the default interface
IP (interface used to connect the node with the default GW) is added into the NAT
main address pool and the interface itself is switched into the post-routing NAT
mode (`output` feature) - both during Resync. The renderer can be initialized
to run in a SNAT-only mode, which leaves the rendering of services to another
renderer but at least provides source-NAT for Internet access.

To work-around the [second listed limitation of the VPP-NAT plugin](#vpp-nat-plugin-limitations),
the renderer runs the method `idleNATSessionCleanup()` inside a go-routine,
periodically cleaning up inactive NAT sessions.

![NAT configuration example][nat-configuration-diagram]

#### SRv6 Renderer
The SRv6 Renderer maps `ContivService` instances into the corresponding [SRv6 model][srv6-model]
instances that are then installed into VPP by the Ligato vpp Agent. See the [SRv6 README](../setup/SRV6.md)
for more details on how SRv6 k8s service rendering works.

[layers-diagram]: services/service-plugin-layers.png "Layering of the Service plugin"
[nat-configuration-diagram]: services/nat-configuration.png "NAT configuration example"
[ks-services]: https://kubernetes.io/docs/concepts/services-networking/service/
[kube-proxy]: https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/
[ipvs]: http://kb.linuxvirtualserver.org/wiki/IPVS
[vpp-nat-plugin]: https://wiki.fd.io/view/VPP/NAT
[vpp-nat-plugin-api]: https://github.com/vpp-dev/vpp/blob/stable-1801-contiv/src/plugins/nat/nat.api
[service-plugin]: https://github.com/contiv/vpp/tree/master/plugins/service
[service-plugin-skeleton]: https://github.com/contiv/vpp/blob/master/plugins/service/plugin_impl_service.go
[cn-infra]: http://github.com/ligato/cn-infra
[processor-api]: http://github.com/contiv/vpp/tree/master/plugins/service/processor/processor_api.go
[processor-data-change]: http://github.com/contiv/vpp/tree/master/plugins/service/processor/data_change.go
[processor-data-resync]: http://github.com/contiv/vpp/tree/master/plugins/service/processor/data_resync.go
[renderer-api]: http://github.com/contiv/vpp/blob/master/plugins/service/renderer/api.go
[nat-model]: https://github.com/ligato/vpp-agent/blob/dev/api/models/vpp/nat/nat.proto
[srv6-model]: https://github.com/ligato/vpp-agent/blob/dev/api/models/vpp/srv6/srv6.proto
[vpp-agent-nat-plugin]: https://github.com/ligato/vpp-agent/tree/dev/plugins/vpp/natplugin
[controller-plugin]: https://github.com/contiv/vpp/blob/master/plugins/controller/plugin_controller.go
[transaction-api]: https://github.com/contiv/vpp/blob/master/plugins/controller/api/txn.go
[ligato-vpp-agent]: http://github.com/ligato/vpp-agent
[policies-dev-guide]: POLICIES.md
[packet-flow-dev-guide]: PACKET_FLOW.md
[portmap-plugin]: https://github.com/containernetworking/plugins/tree/master/plugins/meta/portmap
[pod-model]: http://github.com/contiv/vpp/blob/master/plugins/ksr/model/pod/pod.proto
[svc-model]: https://github.com/contiv/vpp/blob/master/plugins/ksr/model/service/service.proto
[eps-model]: https://github.com/contiv/vpp/blob/master/plugins/ksr/model/endpoints/endpoints.proto
[nodesync-plugin]: https://github.com/contiv/vpp/tree/master/plugins/nodesync
[contiv-cni-conflist]: https://github.com/contiv/vpp/blob/master/docker/vpp-cni/10-contiv-vpp.conflist
[ipnet-plugin]: https://github.com/contiv/vpp/tree/master/plugins/ipnet
[ipam-plugin]: https://github.com/contiv/vpp/tree/master/plugins/ipam
[local-client]: https://github.com/ligato/vpp-agent/tree/dev/clientv2
[event-loop-guide]: EVENT_LOOP.md
[event-handler]: EVENT_LOOP.md#event-handler
[db-resources]: https://github.com/contiv/vpp/tree/master/dbresources
