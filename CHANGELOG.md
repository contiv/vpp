# Release v1.4.0 (future)

### VPP
 - version **18.10-rc0-505**

### Bug Fixes
 - support for more than one IP on the managemnt interface
 - concurrent map access fix in ligato/vpp-agent
 
### New Features
 - option for simplfied IPAM config (`ContivCIDR`)
 - ability to define IPAM via CRD
 - cluster state validator
 - `netctl` command line tool
 
### Known Issues
 - fragmentation issues in STN setup (STN is still experimental)

### Breaking Changes
 - due to new VPP version and some recent changes in the VPP NAT plugin, the following is the new default recommended VPP startup config for the NAT:
 ```
 nat {
   endpoint-dependent
   max translations per user 10000   
}
 ```



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
 
