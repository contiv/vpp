# Multi-master setup

Contiv/VPP supports HA kubernetes cluster that has more than
one master node. Contiv/VPP components running on master nodes only (ksr, crd)
 use etcd election algorithm to ensure that only one of the instances
 is active at a time.

# Exploring multi-master on vagrant setup

Multi-master setup is not supported for arbitrary values of vagrant parameters.
This is caused by different ways of distributing master certificates for various kubernetes version, mainly.

It is recommended to use the following steps: 
```
cd vagrant
# 2 master nodes
export K8S_MASTER_NODES=2
# 2 worker nodes
export K8S_NODES=2
# supported version of kubernetes
export K8S_VERSION=1.13.4
# use dev branch since, there are latest features 
export CONTIV_IMAGE_TAG=dev

./vagrant-up
```