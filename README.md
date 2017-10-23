# Contiv - VPP

[![Build Status](https://travis-ci.org/contiv/vpp.svg?branch=master)](https://travis-ci.org/contiv/vpp)
[![Coverage Status](https://coveralls.io/repos/github/contiv/vpp/badge.svg?branch=master)](https://coveralls.io/github/contiv/vpp?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/contiv/vpp)](https://goreportcard.com/report/github.com/contiv/vpp)
[![GoDoc](https://godoc.org/github.com/contiv/vpp?status.svg)](https://godoc.org/github.com/contiv/vpp)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/contiv/vpp/blob/master/LICENSE)

Please note that the content of this repository is currently **WORK IN PROGRESS**.

This Kubernetes network plugin uses FD.io VPP to provide network connectivity
between PODs. Currently, only single-node k8s clusters are supported, with no
connection to the k8s services running on the host from the PODs.


### Quickstart

#### Step 1 (Optional): Installing CRI Shim on your hosts
If your pods will be using the VPP TCP/IP stack, you must first install the 
CRI Shim on each host where the stack will be used. The CRI Shim installation 
should only be performed after `kubelet`, `kubeadm` and `kubectl` have already
been [installed][2]. 

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh)
```
Note that the CRI Shim installer has only been tested  with the [kubeadm][1]
K8s cluster creation tool. 

After installing the CRI Shim, please proceed with cluster initialization, 
as described in the steps below. Alternatively, if the cluster had already
been initialized before installing the CRI Shim, just reboot the node.


#### Step 2: Initializing your master
Before initializing the master, you may want to clean up any previously 
installed K8s components:
```
sudo su
rm -rf ~/.kube
kubeadm reset
```
After cleanup, proceed with master initialization as described in the 
[kubeadm manual][3]:
```
kubeadm init
```
If Kubernetes was initialized successfully, it prints out this message:
```
Your Kubernetes master has initialized successfully!
```

After successful initialization, don't forget to set up your .kube directory
as a regular user (as instructed by `kubeadm`):
```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

#### Step 3: Installing the Contiv-VPP POD network
If you have already used the Contiv-VPP plugin before, you may need to pull the most recent Docker images on each node:
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)
```

Install the Contiv-VPP network for your cluster as follows:
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
More details about installing the pod network can be found in the 
[kubeadm manual][4]. In particular, if you are installing everything on a
single node, please remember to untaint it:
```
kubectl taint nodes --all node-role.kubernetes.io/master-
``` 

#### Step 4 (Optional): Joining your nodes
If you have more than one worker nodes, you can now join them into the cluster 
as described in the [kubeadm manual][5].

NOTE: multi-node clusters are currently not supported. They will be available 
shortly.

#### Step 5: Verifying the installation
You can go ahead and deploy some PODs, e.g.:
```
$ kubectl run nginx --image=nginx --replicas=2
```

Use `kubectl describe pod` to get the IP address of a POD, e.g.:
```
$ kubectl describe pod nginx | grep IP
```
You should see two ip addresses, for example:
```
IP:		10.1.1.3
IP:		10.1.1.4
```

You can check the connectivity in one of the following ways:
* Connect to the VPP debug CLI and ping any pod:
```
  telnet 0 5002
  vpp# ping 10.1.1.3
```
* Start busybox and ping any pod:
```
  kubectl run busybox --rm -ti --image=busybox /bin/sh
  If you don't see a command prompt, try pressing enter.
  / #  
  / # ping 10.1.1.3

```
* You should be able to ping any pod from the host:
```
  ping 10.1.1.3
```

#### Troubleshooting
Some of the issues that can occur during the installation are:

- Forgetting to create and initialize the `.kube` directory in your home 
  directory (As instructed by `kubeadm init`). This can manifest itself 
  as the following error:
  ```
  W1017 09:25:43.403159    2233 factory_object_mapping.go:423] Failed to download OpenAPI (Get https://192.168.209.128:6443/swagger-2.0.0.pb-v1: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")), falling back to swagger
  Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")
  ``` 
- Previous installation lingering on the file system. `'kubeadm init` fails 
  to initialize kubelet with one or more of the following error messages:
  ```
  ...
  [kubelet-check] It seems like the kubelet isn't running or healthy.
  [kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10255/healthz' failed with error: Get http://localhost:10255/healthz: dial tcp [::1]:10255: getsockopt: connection refused.
  ...
  ```
   
If you run into any of the above issues, try to clean up and reinstall as root:
```
sudo su
rm -rf ~/.kube
kubeadm reset
kubeadm init
```

[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[2]: https://kubernetes.io/docs/setup/independent/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl
[3]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#initializing-your-master
[4]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#pod-network
[5]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#joining-your-nodes
