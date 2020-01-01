### Service Function Chaining in Contiv-VPP

Since Contiv-VPP CNI is aimed mostly for CNF deployments, we decided to support
service function chaining between the pods for CNF workloads directly on the CNI. 

A service function chain defines network interconnections between custom (additional) POD interfaces 
(see [custom interfaces README](../operation/CUSTOM_POD_INTERFACES.md)), and can be defined
as CRDs with references to the PODs via the pod labels, similarly as in k8s services
([example](../../k8s/crd/service-function-chain.yaml)).

Contiv-VPP will support several ways of rendering the service chains. For example,
a service function chain defined as an ordered list of pod labels `app=a, app=b, app=c`
can be rendered either using l2 cross-connects with VXLANs as follows:
![SFC Plugin](sfc/SFC1.png)

or using SRv6 as follows:
![SFC Plugin](sfc/SFC2.png)

## SFC Implementation details
SFC in Contiv-VPP is implemented similarly to [k8s services](SERVICES.md). It consists of
the following components:

 - **SFC reflector in CRD** - reflects SFC defined as CRDs into Contiv-ETCD
 - **SFC Processor** - processes service function chain definitions in abstract format
 (using k8s labels) to chains of actual running pod instances
 - **SFC Renderers** - render service chain instances into VPP configuration (wire,
 or "stitch" pod interfaces on VPP). The CNI may contain different SFC renderers,
 each one doing the stitching differently on VPP, but providing the same functionality,
 e.g. l2xconn renderer or SRv6 renderer.
 

![SFC Plugin](sfc/SFC-plugin-layers.png)


## SRv6 Renderer
The SRv6 renderer uses SRv6 components supported in VPP to create SFC chain. The SFC chain
rendered with the SRv6 renderer always starts with SRv6 steering. The steering forwards the packet 
to the SRv6 policy that determinates the rest of the packet route by using the SRv6 localsid's SIDs. 
For the inner links of chain are always used LocalSID with the End.AD end function (dynamic SR-proxy).
The end link of the SFC chain is localsid with End.DX2/End.DX4/End.DX6 end function depending on the 
end link interface (L2,L3 IPv4/IPV6).

The SRv6 renderer supports:
- [x] Support for L2, L3 IPv4 and L3 IPv6 interfaces (all interfaces going in/out of VPP and that are 
meant for SFC chain must by of the same Layer and address family)    
- [x] SFC chain on multiple nodes
- [x] Pod rescheduling (on the same or different node) with already set SFC chain
- [x] Using 1 or 2 interfaces for communication between SR-Proxy and SR-unaware inner link
- [x] Basic multipaths: multiple pods per inner link of the SFC chain are used to create separate 
paths that is loadbalances by SRv6 policy (1 inner pod can be part of only one path)   
- [x] Support for custom networks (custom pod VRF tables) (supported only L3 IPv6 interfaces because 
L2 implementation is the same as when using stub interfaces and L3 IPv4 implementation would bypass 
almost all custom networks due to the IPv6 nature of SRv6)
- [x] Support for external interfaces(i.e. DPDK) for first and last link of SFC chain       

The SRv6 doesn't support:
- [ ] Bidirectional feature of SFC chain. The SRv6-rendered SFC chain is currently always unidirectional. 
- [ ] Extended multipaths: multipaths with more complicated logic how to create path from pods 
selected for SFC chain
- [ ] Start and end link of SFC chain on the same node (problem with IP collision in the same VRF table)



## SFC implementation progress
**SFC in Contiv-VPP is still work in progress**. The progress is tracked in the following list:

- [X] define service function chain CRD API ([example](../../k8s/crd/servicefunctionchain.yaml))
- [x] SFC CRD reflector on KSR 
- [x] SFC plugin skeleton + SFC Processor
- [x] SRv6 renderer (for supported features see)
- [ ] l2xconn renderer **(in progress)**
