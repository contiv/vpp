# Contiv - VPP

[![Build Status](https://travis-ci.org/contiv/vpp.svg?branch=master)](https://travis-ci.org/contiv/vpp)
[![Coverage Status](https://coveralls.io/repos/github/contiv/vpp/badge.svg?branch=master)](https://coveralls.io/github/contiv/vpp?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/contiv/vpp)](https://goreportcard.com/report/github.com/contiv/vpp)
[![GoDoc](https://godoc.org/github.com/contiv/vpp?status.svg)](https://godoc.org/github.com/contiv/vpp)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/contiv/vpp/blob/master/LICENSE)

Please note that the content of this repository is currently **WORK IN PROGRESS**.

This Kubernetes network plugin uses FD.io VPP to provide the network connectivity between PODs.
Currently, only one-node k8s cluster is supported, with no connection to the k8s services running on the host from the PODs.

### Quickstart

#### 1. (Optional) Install CRI Shim
In case you plan to use fast TCP/UDP features of VPP, install the CRI shim on each host (after Kubernetes has been installed). Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh)
```
Note that this installer has been tested only for
[kubeadm](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/)-managed
clusters. After installing, please proceed with `kubeadm init` and `kubeadm join` workflow to deploy your Kubernetes cluster, or reboot the node if the cluster has been already initialized.

#### 2. Deploy Kubernetes Cluster
Now deploy your k8s cluster, e.g. using [kubeadm](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/).

#### 3. Deploy the Contiv-VPP Network Plugin:
```
kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```

Check the status of the deployment:
```
$ kubectl get pods -n kube-system
NAME                             READY     STATUS    RESTARTS   AGE
NAMESPACE     NAME                             READY     STATUS             RESTARTS   AGE
kube-system   contiv-etcd-cxqhr                1/1       Running            0          1h
kube-system   contiv-ksr-h9vts                 1/1       Running            0          1h
kube-system   contiv-vswitch-9nwwr             2/2       Running            0          1h
```

#### 4. Deploy PODs and Verify:
You can go ahead and deploy some PODs, e.g.:
```
$ kubectl apply -f ubuntu.yaml
```

Use `kubectl describe pod` to get the IP address of a POD, e.g.:
```
$ kubectl describe pod ubuntu | grep IP
IP:		10.0.0.1
```

To check the connectivity, you can connect to VPP debug CLI and execute a ping:
```
telnet 0 5002
vpp# ping 10.0.0.1
```

You should be able to ping the pod from the host as well.
```
ping 10.0.0.1
```