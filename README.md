# Contiv - VPP

![contiv - VPP](https://github.com/contiv/vpp/img/contiv2.png)

Cloud-native splits applications into smaller/modular pieces called microservices. Microservices are packaged up and deployed in containers across a network of physical or virtual hosts. Container-housed microservices communicate with each other across the network to deliver the desired application function. Thus the network plays a crucial role enabling application behavior and performance. 

Contiv-VPP is a new Kubernetes network plugin employing a containerized FD.io dataplane. Highlights include: 

- Containerized FD.io dataplane
- Operates in use-space for rapid upgradability and, no dependency on linux kernel community for network feature enhancements
- Full Kubernetes CNI network plugin support
- Supports Kubernetes network policies and services

Contiv-VPP is built as a Cloud-Native Virtual Network Function (CN-VNF) using components of [Ligato](ligato.io) coupled with the familiar Kubernetes network infrastructure and control. 

### Working with Contiv - VPP

[![Build Status](https://travis-ci.org/contiv/vpp.svg?branch=master)](https://travis-ci.org/contiv/vpp)
[![Coverage Status](https://coveralls.io/repos/github/contiv/vpp/badge.svg?branch=master)](https://coveralls.io/github/contiv/vpp?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/contiv/vpp)](https://goreportcard.com/report/github.com/contiv/vpp)
[![GoDoc](https://godoc.org/github.com/contiv/vpp?status.svg)](https://godoc.org/github.com/contiv/vpp)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/contiv/vpp/blob/master/LICENSE)

This Kubernetes network plugin uses FD.io VPP to provide network connectivity
between PODs. Currently, only Kubernetes 1.9.X and higher versions are supported.


## Quickstart
You can get started with Contiv-VPP in one of two ways:
* Use the [Contiv-VPP Vagrant Installation][1] instructions to start a 
  simulated Kubernetes cluster with a couple of hosts running in VirtualBox
  VMs. This is the easiest way to bring up a cluster for exploring the 
  capabilities and features of Contiv-VPP.
   
* Use the [Contiv-specific kubeadm install][2] instructions to manually
  install Kubernetes with Contiv-VPP networking on one or more bare-metal
  
  
## Reporting Bugs
In order to report a bug, please file an issue in GitHub. Please provide
the information described in [Bug Reports README](docs/BUG_REPORTS.md).


## Contributing

Contributions to VPP-Agent are welcome. We use the standard pull request
model. You can either pick an open issue and assign it to yourself or open
a new issue and discuss your feature.

In any case, before submitting your pull request please check the 
[Coding style][3] and cover the newly added code with tests and 
documentation (Contiv-VPP adopted the coding style used in the [Ligato][5]
project). Upon submission, each patch is run through the `go fmt` and 
`golint` tools.


The tool used for managing third-party dependencies is [Dep][4]. After
 adding or updating a dependency in `Gopkg.toml` run `make install-dep` to 
download the specified dependencies into the vendor folder. Please make sure
that each dependency in the `Gopkg.toml` has a specific `version` defined 
(a specific commit ID or a git tag).

[1]: vagrant/README.md
[2]: docs/MANUAL_INSTALL.md
[3]: https://github.com/ligato/cn-infra/blob/master/docs/guidelines/CODINGSTYLE.md
[4]: https://github.com/golang/dep
[5]: https://github.com/ligato
