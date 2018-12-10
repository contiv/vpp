### VMware vmxnet3 driver support

This page describes the usage of the VPP's 
[native PCI driver support for VMware vmxnet3](https://docs.fd.io/vpp/18.10/md_src_plugins_vmxnet3_README.html) 
with Contiv/VPP.

## Prerequisites

- `vfio-pci` driver needs to be loaded (execute `modprobe vfio-pci` or add `vfio-pci` into the `/etc/modules`)

- on systems without IOMMU, enable unsafe [No-IOMMU mode](https://lwn.net/Articles/660745/):
```
# option 1: works immediately, but only until the node is rebooted
echo "1" > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# option 2: works after reboot:
echo "options vfio enable_unsafe_noiommu_mode=1" > /etc/modprobe.d/vfio-noiommu.conf
```

- PCI devices must be disabled in the DPDK section of the VPP startup config file in `/etc/vpp/contiv-vswitch.conf`:
```
dpdk {
  no-pci
}
```

## Configuration
To configure a vmxnte3 interface, `MainVppInterface` with the prefix `vmxnet3-` must be configured in the 
`NodeConfig` section of the deployment yaml. After the `vmxnet3-` prefix, the device's PCI address is encoded,
e.g. the device with pCI address `0000:0b:00.0` renders into the interface name `vmxnet3-0/b/0/0`.


Also, since contrary to the DPDK interfaces, the vmxnet3 interfaces support also non-polling 
interface rx modes, it is a good idea to configure the `interrupt` or `adaptive` `InterfaceRxMode`.

Example configuration:
```diff
iff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index 83909b1c2..346a1b2b1 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -36,6 +40,7 @@ data:
     ServiceLocalEndpointWeight: 1
     DisableNATVirtualReassembly: false
     CRDNodeConfigurationDisabled: true
+    InterfaceRxMode: adaptive
     IPAMConfig:
       NodeInterconnectDHCP: false
       NodeInterconnectCIDR: 192.168.16.0/24
@@ -45,6 +50,13 @@ data:
       VPPHostSubnetCIDR: 172.30.0.0/16
       VPPHostNetworkPrefixLen: 24
       VxlanCIDR: 192.168.30.0/24
+    NodeConfig:
+    - NodeName: ubuntu-server-1
+      MainVppInterface:
+        InterfaceName: vmxnet3-0/b/0/0
+    - NodeName: ubuntu-server-2
+      MainVppInterface:
+        InterfaceName: vmxnet3-0/b/0/0
   logs.conf: |
     default-level: debug
     loggers:
``` 

Please note that this config can be specified using the [helm chart](../k8s/contiv-vpp), 
and the node config also via CRD.