# Release v3.3.2 (2019-10-16)

### VPP
 - version **v19.08.1**

### New Features & Enhancements
 - k8s 1.16 support
 - support for [L3 custom networks](k8s/examples/custom-network) defined in CRDs

### Bugfixes
 - fixed crash issue of vmxnet3 interfaces

### Known Issues
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.3.1 (2019-09-20)

### VPP
 - version **v19.08** (latest stable/1908)

### Bugfixes
 - address CVE-2019-9512 and CVE-2019-9514 issues
 - fix SplitHorizonGroup for [L2 custom networks](k8s/examples/custom-network)

### Known Issues
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.3.0 (2019-09-06)

### VPP
 - version **v19.08** (latest stable/1908)

### New Features & Enhancements
 - support for cluster-wide L2 cross-connect based [service chaining between pods](k8s/examples/sfc/README.md)
 - support for [custom networks](k8s/examples/custom-network) defined in CRDs
 - support for [external interfaces](k8s/examples/custom-network) defined in CRDs

### Bugfixes
 - fixed VPP NAT in multi-worker setup

### Known Issues
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.2.1 (2019-07-24)

### VPP
 - version **v19.04** (latest stable/1904)

### Bugfixes
 - fixed GSO (Generic Segmentation Offload) issue on VPP
 - fixed an SRv6 k8s service implementation issue

### Known Issues
 - GSO does not work correctly with SRv6
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.2.0 (2019-07-02)

### VPP
 - version **v19.04** (latest stable/1904)

### New Features & Enhancements
 - GSO (Generic Segmentation Offload) is enabled on VPP by default, which brings better performance
 for pod-to-pod communication via TAP interfaces
 - SRv6 as a new node-to-node transport option
 - new helm option `contiv.nodeToNodeTransport` with possible values: `vxlan` (default), `srv6`, or `nooverlay`
 - experimental (PoC) support for [service chaining between pods](k8s/examples/sfc/README.md)

### Known Issues
 - (IPv6 only): service load-balancing in IPv6 setup is not equal, node-local backend pods are always
   preferred and a request is never load-balanced to a remote node's pod if there is a local backend
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.1.0 (2019-05-17)

### VPP
 - version **v19.01** (latest stable/1901)

### New Features & Enhancements
 - update to vpp-agent `v2.1.0`
 - [multi-master](docs/setup/MULTI_MASTER.md) and [external ETCD](docs/setup/EXTERNAL_ETCD.md) support
 - experimental [SRv6 implementation of k8s services](docs/setup/SRV6.md)
 - experimental support for [multiple pod interfaces](docs/operation/CUSTOM_POD_INTERFACES.md), 
 including memif interfaces
 - load-balancing between backends of a service now supports unlimited backend pod count

### Known Issues
 - (IPv6 only): service load-balancing in IPv6 setup is not equal, node-local backend pods are always
   preferred and a request is never load-balanced to a remote node's pod if there is a local backend
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.0.1 (2019-04-08)

### VPP
 - version **v18.10** (latest stable/1810)

### Bugfixes
 - update to vpp-agent `v2.0.1` (includes a GoVPP fix for unix-domain socket communication)
 - fixed IPv6 policy rendering for host-network pods

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)
 - (IPv6 only): service load-balancing in IPv6 setup is not equal, node-local backend pods are always
   preferred and a request is never load-balanced to a remote node's pod if there is a local backend
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v3.0.0 (2019-04-04)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - [IPv6 Support](docs/setup/IPV6.md)
 - internal process manager is now used to manage Contiv-Agent & VPP processes inside of the
   vswitch container (instead of the supervisor tool)
 - ability to use unix domain socket for connection to VPP for better performance
   (`contiv.vswitch.useSocketVPPConnection` helm option)
 - `contiv.useL2Interconnect` helm option renamed to `contiv.useNoOverlay`
 - Vagrant optimized to boot faster using pre-build images

### Bugfixes
 - fixed Prometheus stats exporter

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)
 - (IPv6 only): service load-balancing in IPv6 setup is not equal, node-local backend pods are always
   preferred and a request is never load-balanced to a remote node's pod if there is a local backend
 - (IPv6 only): network Policies are implemented using ip6tables rules in individual pods. Because of
   this, the policy programming is a bit slower (compared to policy programming on VPP for IPv4)


# Release v2.1.4 (21.3.2019)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - added `etcd.service.useNodeIP` HELM option

### Bugfixes
 - vswitch base image updated to the newest ubuntu:18.04 build, which fixes some security vulnerabilities

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)


# Release v2.1.3 (26.2.2019)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - use helm chart version as the default tag for contiv images in the helm template

### Bugfixes
 - fixed some Contiv UI issues

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)


# Release v2.1.2 (7.2. 2019)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - global helm option for default gateway
 - documentation & dev guide

### Bugfixes
 - fixed issue where default route in pod was not configured after IP address change

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)

# Release v2.1.1 (24.1.2019)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - default ETCD version update to 3.3.11
 - enhanced `vppctl` script

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)

# Release v2.1.0 (16.1.2019)

### VPP
 - version **v18.10** (latest stable/1810)

### New Features & Enhancements
 - both Contiv/VPP and the underlying ligato/VPP-Agent have underwent a major
   **refactoring**
 - VPP-Agent is now based on a newly implemented framework, called **kvscheduler**,
   providing **transaction-based** configuration processing with a generic mechanism
   for dependency resolution between configuration items, which in effect simplifies
   and unifies the configurators
 - for Contiv, the VPP-Agent refactor yields more **stability** and also
   **visibility** to what changes are being made in the configuration in the form
   of additional REST interfaces and with much more readable and compact logs
 - Contiv/VPP itself has been refactored into a **synchronous event-driven**
   control-flow model, further simplifying debugging and limiting potential
   race conditions
 - the previously bloated `contiv` plugin has been split into multiple smaller
   plugins to improve readability and **modularity** - it will be substantially
   easier in the future to add new features as separate plugins without
   the need to change anything or too much of the existing code base, potentially
   opening Contiv/VPP for external contributors
 - the support for re-synchronization has been fine-tuned to ensure that the
   system state gets properly recovered after a restart or any kind of failure/outage
 - network **configuration is no longer persisted** in `etcd`, mitigating the load
   onto the datastore, instead the agent is now able to re-calculate the full
   configuration state on demand (only Kubernetes state remains reflected
   into `etcd` by KSR)
 - Kubernetes state data are also **mirrored** from `etcd` into local `bolt` DB
   on every node, allowing the agent to restart and recover the state without
   immediate connectivity to `etcd`
 - run-time change of the DHPC-assigned main IP address is now supported
 - run-time change of `NodeConfig` CRD is now also properly applied without
   the need for a hard restart
 - external applications are able to **extend/customize** the Contiv dataplane
   by submitting additional configuration via `etcd` or `gRPC` API, which then
   gets merged with Contiv's own internal configuration before it gets applied
   to VPP-Agent - more information are available [here](docs/dev-guide/EXTERNAL_CONFIG.md)
 - L2 (no overlay) networking mode is again supported
 - `podVPPSubnetCIDR` has been removed, POD-facing interfaces on VPP are now unnumbered

### Known Issues
 - load-balancing between backends of a service is limited to the first 256 PODs
   (the others will not receive any traffic until some of the first 256 PODs disappear)

# Release v2.0.3 (10.12.2018)

### VPP
 - version **v18.10** (latest stable/1810)

### Bug Fixes
 - fix contiv-netctl when http uses self-signed certs

### New Features & Enhancements
 - added `cipherSuites` option for etcd into helm
 - [native PCI driver support for VMware vmxnet3](docs/setup/VMXNET3.md)

### Known Issues
- load-balancing between backends of a service is limited to the first 256 PODs
(the others will not receive any traffic until some of the first 256 PODs disappear)


# Release v2.0.2 (29.11.2018)

### VPP
 - version **v18.10** (latest stable/1810)

### Bug Fixes
 - fixed various NAT (high load) & ACL (large scale) issues on VPP
 - do not route ServiceCIDR towards VPP from Linux by default
 - minor vpp-agent infra fixes

### New Features & Enhancements
 - mark ETCD disconnect as non-fatal for liveness & readiness probe in KSR & CRD
 - parametrized liveness & readiness probe intervals for all components
 - parametrized CPU requests for all Contiv components

### Known Issues
- load-balancing between backends of a service is limited to the first 256 PODs
(the others will not receive any traffic until some of the first 256 PODs disappear)


# Release v2.0.1 (21.11.2018)

### VPP
 - version **v18.10** (latest stable/1810)

### Bug Fixes
 - use parametrized ETCD image repo&tag in the vswitch init container

### New Features & Enhancements
 - lowered log verbosity
 - minor CRD improvements


# Release v2.0.0 (9.11.2018)

### VPP
 - version **v18.10** (formal release)

### Bug Fixes
 - properly handle change events in service processor before the first resync
 - close opened fd on unsuccessful switch to network ns

### New Features & Enhancements
 - netctl supports clusters where etcd & rest is secured


# Release v1.5.1 (31.10.2018)

### VPP
 - version **v18.10** (formal release)

### Bug Fixes
 - fix nodePort issues after change of management IP address between restarts
 - STN: Fix proxy ARP for /31 subnets

### New Features & Enhancements
 - bump ETCD version to 3.3.10
 - add new liveness probe for Contiv ETCD
 - Policy Configurator: test for rule duplicity in O(log(n)) time
 - remove persistent storage for IPAM (use ETCD instead)
 - topology validator enhancements


# Release v1.5.0 (19.10.2018)

### VPP
 - version **v18.10-rc1~15-g347c523**

### Bug Fixes
 - race condition in DHCP notification handling
 - added missing pull policy for init containers
 - fixed issues in STN setup
 - fixed some `contiv-netctl` and CRD issues
 - minor IPAM fixes

### New Features & Enhancements
 - better handling of identity NAT on VPP
 - k8s 1.12 compatibility

### Known Issues
- the topology validator gives false positives for L3-FIB entries


# Release v1.4.0 (5.10.2018)

### VPP
 - version **18.10-rc0-505**

### Bug Fixes
 - support for more than one IP on the management interface
 - concurrent map access fix in ligato/vpp-agent

### New Features
 - option for simplified IPAM config (`ContivCIDR`)
 - ability to define IPAM via CRD
 - cluster state validator
 - `contiv-netctl` command line tool

### Known Issues
 - fragmentation issues in STN setup (STN is still experimental)

### Breaking Changes
 - due to new VPP version and some recent changes in the VPP NAT plugin, the following is the new default recommended VPP startup config for the NAT:
 ```
nat {
    endpoint-dependent
    translation hash buckets 1048576
    translation hash memory 268435456
    user hash buckets 1024
    max translations per user 10000
}
 ```
(for more details see [VPP NAT Documentation](https://wiki.fd.io/view/VPP/NAT#Startup_config)).


# Release v1.3.0 (18.9.2018)

### VPP
 - version **18.04 stable** + Contiv bugfixes

### Bug Fixes
 - lots of bugfixes in both VPP and Contiv.

### Known Issues
 - MTU-related issues in STN setup (STN is still experimental).



# Release v1.2.0 (5.9.2018)

### VPP
 - version **18.04 stable** + Contiv bugfixes

### New Features
 - dedicated POD VRF and interconnect VRF,
 - local Bolt DB used for IPAM storage,
 - port names fully supported in k8s policies.

### Bug Fixes
 - most of NAT related issues fixed in STN setup.
 - lots of other bugfixes in both VPP and Contiv.

### Known Issues
 - MTU-related issues in STN setup (STN is still experimental).



# Release v1.1.0 (13.6.2018)

### VPP
 - version **18.01 stable** + Contiv bugfixes

### New Features
 - vSwitch POD waits for ETCD becoming ready before starting,
 - secured internal GRPC connections (CNI, STN),
 - options for securing connections to Contiv ETCD & Contiv Agent HTTP services,
 - configurable IP neighbor scanning.

### Bug Fixes
 - fixed issues in some restart / upgrade scenarios,
 - Gratuitous ARP fix on VPP.

### Known Issues
 - port names not fully supported in k8s policies,
 - NAT-related issues in STN setup (STN is still experimental).



# Release v1.0.0 (18.5.2018)

### VPP
 - version **18.01 stable** + Contiv bugfixes

### New Features
 - full k8s services support,
 - full k8s policies support,
 - support for vSwitch / node restarts,
 - experimental STN (Steal The NIC) functionality.

### Known Issues
 - connection to Contiv ETCD, HTTP services and internal GRPC connections (CNI, STN) are not secured,
 - port names not fully supported in k8s policies,
 - NAT-related issues in STN setup (STN is still experimental).

