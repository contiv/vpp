# Manual Installation on Arm64 Platform
Now the Contiv-VPP can also support Arm64 platform. Most of installation steps are the
same as that described in [MANUAL_INSTALL][1], so you should firstly read [it][1] before
you start the installation on Arm64 platform.

This document gives out the extra description for Arm64 platfrom to manually install
Kubernetes with Contiv-VPP networking on one or more bare metal or VM hosts.


## Prepare Docker Images for Arm64 platform
In general, the needed docker images of all Contiv-VPP components, including contivvpp/vswitch,
contivvpp/cni, contivvpp/ksr, contivvpp/stn for arm64 platform can be pulled from Contiv-VPP
official docker hub repository, such as:
  ```
  $ sudo docker pull contivvpp/vswitch-arm64:latest
  ```

or just pull all docker images:
  ```
  $ cd k8s
  $ sudo ./pull-images.sh
  ```

If you want to use the latest source code to build for your own on Arm64 platform:

  ```
  $ cd docker
  $ sudo ./build-all.sh -s
  $ sudo ./push-all.sh -s
  ```

or just:
  ```
  $ sudo make docker-images
  ```

## Install the Contiv-VPP pod network
Install the Contiv-VPP network for your cluster on Arm64 platform as follows:
  ```
  kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-arm64.yaml
  ```

- If you want to use the STN feature, the STN configuration is the same as [here][5].

- If you need to generate a manifest file for your arm64 environment, you can use:
  ```
  $ make generate-manifest-arm64
  ```

### Setting up the vswitch to use Network Adapters
For arm64, usually setting up the vswitch to use the network adapters is the same as
that indicated in [MANUAL_INSTALL][1]:

 - [Setup on a node with a single NIC][6]
 - [Setup a node with multiple NICs][7]


## Installation on Cavium Thunderx Arm Server
In general, you can just install Contiv-VPP the same as that described in [MANUAL_INSTALL][1]
if your network environment, such as NICs used for VPP/DPDK, uses the PCI addresses decribed
in the [Determining Network Adapter PCI addresses][8].

* For Cavium Thunderx Arm server, there may need some special processing when you need to use the
generic NICs of it. You can refer to [CAVIUM_MANUAL_INSTALLATION][2] to manually install Contiv-VPP
on Cavium Thunderx servers.

* For the hardware interface configuration on Cavium Thunderx server, you can refer
[CAVIUM_THUNDERX_VPP_CONFIGURATION][4].

* For the multi-NIC setup on Cavium Thunderx server, you can refer
[CAVIUM_THUNDERX_MULTI_NIC_SETUP][3].



[1]: ../MANUAL_INSTALL.md
[2]: MANUAL_INSTALL_CAVIUM.md
[3]: MULTI_NIC_SETUP_CAVIUM.md
[4]: VPP_CONFIG_CAVIUM.md
[5]: ../SINGLE_NIC_SETUP.md#configuring-stn-in-contiv-vpp-k8s-deployment-files
[6]: ../SINGLE_NIC_SETUP.md
[7]: ../MULTI_NIC_SETUP.md
[8]: ../MANUAL_INSTALL.md#determining-network-adapter-pci-addresses

