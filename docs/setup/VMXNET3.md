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
diff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index 8d1d270a0..4b249c349 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -26,6 +26,7 @@ data:
     tapInterfaceVersion: 2
     tapv2RxRingSize: 256
     tapv2TxRingSize: 256
+    interfaceRxMode: "adaptive"
     tcpChecksumOffloadDisabled: true
     natExternalTraffic: true
     mtuSize: 1450
@@ -44,6 +45,12 @@ data:
       vppHostSubnetCIDR: 172.30.0.0/16
       vppHostSubnetOneNodePrefixLen: 24
       vxlanCIDR: 192.168.30.0/24
+    nodeConfig:
+    - nodeName: ubuntu-server-1
+      mainVppInterface:
+        interfaceName: vmxnet3-0/b/0/0
+    - nodeName: ubuntu-server-2
+      mainVppInterface:
+        interfaceName: vmxnet3-0/b/0/0
   controller.conf: |
     delayLocalResync: 5000000000
     enablePeriodicHealing: false
``` 

Please note that this config can be specified using the [helm chart](../../k8s/contiv-vpp), 
and the node config also via CRD.

## STN Usage
Vmxnet3 VPP driver can also be used in the [STN (single NIC) mode](SINGLE_NIC_SETUP.md).
In this case, you need to specify `stealInterface` as usually. In case that the
`vmxnet3` kernel driver was  used in the host OS before stealing the NIC, vmxnet3 driver
will be automatically used.

Example configuration:

```diff
diff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index 8d1d270a0..4b249c349 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -26,6 +26,7 @@ data:
     tapInterfaceVersion: 2
     tapv2RxRingSize: 256
     tapv2TxRingSize: 256
+    interfaceRxMode: "adaptive"
     tcpChecksumOffloadDisabled: true
     natExternalTraffic: true
     mtuSize: 1450
@@ -44,6 +45,12 @@ data:
       vppHostSubnetCIDR: 172.30.0.0/16
       vppHostSubnetOneNodePrefixLen: 24
       vxlanCIDR: 192.168.30.0/24
+    nodeConfig:
+    - nodeName: ubuntu-server-1
+      stealInterface: ens192
   controller.conf: |
     delayLocalResync: 5000000000
     enablePeriodicHealing: false
```