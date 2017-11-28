## Contiv-VPP Kubernetes Deployment Files

This folder contains a set of files that can be used to deploy Contiv-VPP
network plugin on Kubernetes.

#### contiv-vpp.yaml
The main deployment file that can be used to deploy Contiv-VPP network plugin using `kubeadm`:
```
# deploy
kubectl apply -f contiv-vpp.yaml

# undeploy
kubectl delete -f contiv-vpp.yaml
```
Optionaly you can edit `contiv-vpp.yaml` to deploy the dev-contiv-vswitch image, built
in local environment with `../docker/build-all.sh`.
```
sed -i "s@image: contivvpp/vswitch@image: dev-contiv-vswitch:<your image version>@g" ./contiv-vpp.yaml
```

To use the development image for testing with specific version of VPP, see
[DEVIMAGE.md](../docker/DEVIMAGE.md).

#### cri-install.sh
Contiv-VPP CRI Shim installer / uninstaller, that can be used as follows:
```
# install
./cri-install.sh

# uninstall
./cri-install.sh --uninstall
```

#### proxy-install.sh
Pre-installs custom version of Kube-Proxy that works with the Contiv-VPP. Needs to be done
on each node, before initializing the cluster with `kubeadm init` or joining the cluster with `kubeadm join`.
```
./proxy-install.sh
```

#### pull-images.sh
This script can be used to pull the newest version of the `:latest` tag of all Docker images
that Contiv-VPP plugin uses. This may be needed in case that you have already used Contiv-VPP plugin
on the host before and have the old (outdated) versions of docker images stored locally.

#### setup-node.sh
This script simplifies the setup of multi-node cluster - installs DPDK kernel module, pull the images, interactively creates startup config for vpp,... It has to be
executed on each node of the cluster.
```
./setup-node.sh
#########################################
#   Contiv - VPP                        #
#########################################
Do you want to setup multinode cluster? [Y/n] y
PCI UIO driver is not loaded
Do you want to load PCI UIO driver? [Y/n] y
[sudo] password for lukas:
Do you want the PCI UIO driver to be loaded on boot up? [Y/n] y
Module uio_pci_generic was added into /etc/modules
The following network devices were found
1) eth0 0000:00:03.0
2) eth1 0000:00:08.0
3) eth2 0000:00:09.0
Select interface for node interconnect [1-3]:3
Device 'eth2' must be shutdown, do you want to proceed? [Y/n] y

unix {
   nodaemon
   cli-listen 0.0.0.0:5002
   cli-no-pager
}
dpdk {
   dev 0000:00:09.0
}

File /etc/vpp/contiv-vswitch.conf will be modified, do you want to proceed? [Y/n] y
Configuration of the node finished successfully.

```