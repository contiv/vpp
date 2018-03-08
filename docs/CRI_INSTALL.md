### Installing the CRI Shim on your hosts
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

[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[2]: https://kubernetes.io/docs/setup/independent/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl
