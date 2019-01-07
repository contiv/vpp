# Release v2.1.0 (TBD)
TBD

# Release v2.0.3 (10.12.2018)

### VPP
 - version **v18.10** (latest stable/1810)

### Bug Fixes
 - fix contiv-netctl when http uses self-signed certs

### New Features & Enhancements
 - added `cipherSuites` option for etcd into helm
 - [native PCI driver support for VMware vmxnet3](docs/VMXNET3.md)

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
 
