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
 
