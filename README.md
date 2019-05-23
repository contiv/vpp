# Contiv - VPP

[![Build Status](https://travis-ci.org/contiv/vpp.svg?branch=master)](https://travis-ci.org/contiv/vpp)
[![Coverage Status](https://coveralls.io/repos/github/contiv/vpp/badge.svg?branch=master)](https://coveralls.io/github/contiv/vpp?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/contiv/vpp)](https://goreportcard.com/report/github.com/contiv/vpp)
[![GoDoc](https://godoc.org/github.com/contiv/vpp?status.svg)](https://godoc.org/github.com/contiv/vpp)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/contiv/vpp/blob/master/LICENSE)

[Contiv-VPP](https://contivpp.io/) is a Kubernetes CNI plugin for Kubernetes that employs
a programmable [CNF vSwitch](docs/ARCHITECTURE.md) based on [FD.io VPP](https://fd.io/)
offering feature-rich, high-performance cloud-native networking and services.

For more details see [https://contivpp.io/](https://contivpp.io/)


## Features
* kube-proxy implementation on VPP - in the userspace (full implemenatation of [k8s services](docs/dev-guide/SERVICES.md) & [k8s policies](docs/dev-guide/POLICIES.md))
* support for [multiple interfaces per pod](docs/operation/CUSTOM_POD_INTERFACES.md), including memif interfaces
* [IPv6 support](master/docs/setup/IPV6.md), segment routing implementation of k8s services ([SRv6](docs/setup/SRV6.md))
* (in progress) service function chaining between the pods for CNF workloads


## Releases
|Release|Version|Date|
|---|---|---|
|Latest stable release|[![Latest release](https://img.shields.io/github/release/contiv/vpp.svg)](https://github.com/contiv/vpp/releases/latest)|[![release date](https://img.shields.io/github/release-date/contiv/vpp.svg?style=flat)](https://github.com/contiv/vpp/releases/latest)|

Please see the [CHANGELOG](CHANGELOG.md) for a full list of changes on every release.


## Documentation
The [docs folder](docs) contains lots of documentation. For the beginning, you can start with:
* [ARCHITECTURE](docs/ARCHITECTURE.md) for high-level description of Contiv-VPP
  components and operation,
* [NETWORKING](docs/NETWORKING.md) for detailed description on how the network
  is programmed with Contiv-VPP,
* [DEVELOPER GUIDE](docs/dev-guide) for details on how Contiv-VPP works internally.


## Quickstart
You can get started with Contiv-VPP in one of the following ways:
* Use the [Contiv-VPP Vagrant Installation](vagrant/README.md) instructions to start a
  simulated Kubernetes cluster with a couple of hosts running in VirtualBox
  VMs. This is the easiest way to bring up a cluster for exploring the
  capabilities and features of Contiv-VPP.

* Use the [Contiv-specific kubeadm install](docs/setup/MANUAL_INSTALL.md)
  instructions to manually install Kubernetes with Contiv-VPP networking on one
  or more bare-metal servers.

* Use the [Arm64-specific kubeadm install](docs/arm64/MANUAL_INSTALL_ARM64.md)
  instructions to manually install Kubernetes with Contiv-VPP networking on one or more
  bare-metal servers of Arm64 platform.

* Use the [Calico-VPP Vagrant](vagrant/calico-vpp/README.md) to explore deployment of VPP
  in Calico clusters, where some of the nodes can be running plain Calico (without VPP)
  and some of the nodes can be running Calico with VPP.

* Try [Contiv-VPP UI](ui/README.md) web browser user interface on top of Contiv-VPP,
  it runs in Vagrant deployments as well as on bare-metal.


## Configuration & Troubleshooting
Please refer to the [Contiv-VPP configuration and troubleshooting](docs/operation/TOOLS.md) document.


## Reporting Bugs
In order to report a bug, please file an issue in GitHub. Please provide
the information described in [Bug Reports README](docs/debugging/BUG_REPORTS.md).


## Communication Channels
Slack Channel: [https://contivvpp.slack.com/](https://contivvpp.slack.com/)


## Contributing
If you are interested in contributing, please see the [contribution guidelines](docs/dev-guide/CONTRIBUTING.md).
