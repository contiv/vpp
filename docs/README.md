# Contiv-VPP Documentation


## General Information:
* [ARCHITECTURE](ARCHITECTURE.md) - high-level description of Contiv-VPP
  components and operation
* [NETWORKING](NETWORKING.md) - detailed description on how the network
  is programmed with Contiv-VPP
* [DEVELOPER GUIDE](dev-guide) -  details on how Contiv-VPP works internally


## Setup Instructions
* [VAGRANT INSTALLATION](../vagrant/README.md) - running Contiv-VPP in Vagrant
* [MANUAL INSTALLATION](setup/MANUAL_INSTALL.md) - running Contiv-VPP on bare metal
* [IPV6](setup/IPV6.md) - enabling IPv6 in Contiv-VPP
* [ARM64 SETUP](arm64) - running Contiv-VPP on ARM platform
* [CUSTOM MGMT NETWORK](setup/CUSTOM_MGMT_NETWORK.md) - setting up a custom management 
  network on multi-homed nodes
* [MULTI NIC SETUP](setup/MULTI_NIC_SETUP.md) - setting up a node with multiple NICs
* [SINGLE NIC SETUP](setup/SINGLE_NIC_SETUP.md) - setting up a node with a single NIC
* [VMXNET3](setup/VMXNET3.md) - VMware vmxnet3 driver support
* [VPP CONFIG](setup/VPP_CONFIG.md) - creating VPP startup configuration
* [VMWARE FUSION HOST](setup/VMWARE_FUSION_HOST.md) - preparing a VmWare Fusion host
* [ETCD SECURITY](setup/ETCD_SECURITY.md) - securing access to ETCD
* [EXTERNAL_ETCD](setup/EXTERNAL_ETCD.md) - usage of external ETCD instance
* [HTTP SECURITY](setup/HTTP_SECURITY.md) - securing HTTP endpoints
* [MULTI_MASTER](setup/MULTI_MASTER.md) - HA kubernetes setup


## Operation
* [TOOLS](operation/TOOLS.md) - configuration and Troubleshooting Tools
* [PROMETHEUS](operation/PROMETHEUS.md) - Prometheus statistics
* [CONTIV UI](../ui/README.md) - web-based Contiv VPP user interface


## Debugging
* [VPP PACKET TRACING](debugging/VPP_PACKET_TRACING_K8S.md) - how to do VPP packet tracing in Kubernetes
* [VPPTRACE](debugging/VPPTRACE.md) - VPP packet tracing
* [CORE FILES](debugging/CORE_FILES.md) - capturing VPP core dumps
* [BUG REPORTS](debugging/BUG_REPORTS.md) - debugging and reporting bugs in Contiv-VPP
