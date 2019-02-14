# Manual Installation
This document describes how to use [kubeadm][1] to manually install Kubernetes
with Contiv-VPP networking on one or more bare metal or VM hosts.

The manual installation consists of the following steps:
1. [Preparing the nodes](#1.-preparing-the-nodes):
   1. [Setting up network adapter(s)](#1.1.-setting-up-network-adapter(s))
   2. [Setting up the VPP vSwitch to use the network adapters](#1.2.-setting-up-the-vpp-vswitch-to-use-the-network-adapters)
3. [Installing & intializing Kubernetes (using kubeadm)](#2.-installing-&-intializing-kubernetes-(using-kubeadm))
3. [Installing the Contiv-VPP CNI plugin](#4.-installing-the-contiv-vpp-cni-plugin)

After successful installation, you can perform the following tasks:
* [Deployment Verification](#deployment-verification)
* [Uninstalling Contiv-VPP](#uninstalling-contiv-vpp)
* [Tearing down Kubernetes](#tearing-down-kubernetes)


## 1. Preparing the nodes

#### Host-specific configurations
- **VmWare VMs**: the vmxnet3 driver is required on each interface that will
  be used by VPP. Please see [here][13] for instructions how to install the
  vmxnet3 driver on VmWare Fusion.

#### Using the node setup script
The node preparation steps described below can be also performed using the interactive
[node setup script][17].


#### 1.1. Setting up network adapter(s)
DPDK provides access to the NIC for VPPs running on each node in the cluster. 
Therefore, this setup must be completed **on each node** in the cluster.

#### Setting up DPDK
There are 2 DPDK-compatible drivers, `vfio-pci` (preferred on newer systems, 
such as Ubuntu 18.04) and `uio_pci_generic` (works on older systems, such as Ubuntu 16.04).
The following guide will use the `uio_pci_generic` driver, but you can change it to 
`vfio-pci` if it works well on your system.

- Load the PCI driver:
  ```
  $ sudo modprobe uio_pci_generic
  ```

- Verify that the PCI driver has loaded successfully:
  ```
  $ lsmod | grep uio
  uio_pci_generic        16384  0
  uio                    20480  1 uio_pci_generic
  ```

  Please note that the PCI driver needs to be loaded upon each server bootup,
  so you may want to add `uio_pci_generic` into the `/etc/modules` file,
  or a file in the `/etc/modules-load.d/` directory. For example, the
  `/etc/modules` file could look as follows:
  ```
  # /etc/modules: kernel modules to load at boot time.
  #
  # This file contains the names of kernel modules that should be loaded
  # at boot time, one per line. Lines beginning with "#" are ignored.
  uio_pci_generic
  ```

### 1.2. Setting up the VPP vSwitch to use the network adapters
Next, you need to set up the vswitch to use the network adapters in one of the two modes:

- [Setup a node with multiple NICs][14] (preferred; one NIC for management and one for VPP)
- [Setup on a node with a single NIC][15] (for nodes with only single NIC)


## 2. Installing & intializing Kubernetes (using kubeadm)
After the nodes you will be using in your K8s cluster are prepared, you can
install the cluster using [kubeadm][1].

### Installing Kubeadm on your hosts
For first-time installation, see [Installing kubeadm][6]. To update an
existing installation,  you should do a `apt-get update && apt-get upgrade`
or `yum update` to get the latest version of kubeadm.

On each host with multiple NICs where the NIC that will be used for Kubernetes
management traffic is not the one pointed to by the default route out of the
host, a [custom management network][12] for Kubernetes must be configured.


#### Hugepages (Kubernetes 1.10 and above)
VPP requires hugepages to run during VPP operation, to manage large pages of memory. 
In K8s 1.10, the support for 
[huge pages in PODs](https://kubernetes.io/docs/tasks/manage-hugepages/scheduling-hugepages/) 
has been introduced. Since then, this feature must be either disabled or memory limit
must be defined for the vSwitch container.

(a) To disable huge pages, perform the following steps as root:
* Using your favorite editor, disable huge pages in the kubelet configuration
  file (`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` or `/etc/default/kubelet` for version 1.11+):
```
  Environment="KUBELET_EXTRA_ARGS=--feature-gates HugePages=false"
```
* Restart the kubelet daemon:
```
  systemctl daemon-reload
  systemctl restart kubelet
```

(b) To define memory limit for the vSwitch container, append the following snippet to vswitch container in deployment yaml file:
```yaml
    resources:
      limits:
        hugepages-2Mi: 1024Mi
        memory: 1024Mi
```
or set `contiv.vswitch.defineMemoryLimits` to `true` in [helm values](../../k8s/contiv-vpp/README.md).


### Initializing your master
Before initializing the master, you may want to [tear down][8] up any
previously installed K8s components. Then, proceed with master initialization
as described in the [kubeadm manual][3]. Execute the following command as
root:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16
```
**Note:** `kubeadm init` will autodetect the network interface to advertise
the master on as the interface with the default gateway. If you want to use a
different interface (i.e. a custom management network setup), specify the
`--apiserver-advertise-address=<ip-address>` argument to kubeadm init. For
example:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16 --apiserver-advertise-address=192.168.56.106
```
**Note:** The CIDR specified with the flag `--pod-network-cidr` is used by
kube-proxy, and it **must include** the `PodSubnetCIDR` from the `IPAMConfig`
section in the Contiv-vpp config map in Contiv-vpp's deployment file
([contiv-vpp.yaml](../../k8s/contiv-vpp.yaml)). Pods in the host network namespace
are a special case; they share their respective interfaces and IP addresses with
the host. For proxying to work properly it is therefore required for services
with backends running on the host to also **include the node management IP**
within the `--pod-network-cidr` subnet. For example, with the default
`PodSubnetCIDR=10.1.0.0/16` and `PodVPPSubnetCIDR=10.2.1.0/24`, the subnet
`10.3.0.0/16` could be allocated for the management network and
`--pod-network-cidr` could be defined as `10.0.0.0/8`, so as to include IP
addresses of all pods in all network namespaces:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.0.0.0/8 --apiserver-advertise-address=10.3.1.1
```

If Kubernetes was initialized successfully, it prints out this message:
```
Your Kubernetes master has initialized successfully!
```

After successful initialization, don't forget to set up your `.kube` directory
as a regular user (as instructed by `kubeadm`):
```
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

#### Master Isolation (Optional)
By default, your cluster will not schedule pods on the master for security
reasons. If you want to be able to schedule pods on the master, e.g. for a
single-machine Kubernetes cluster for development, run:

```
kubectl taint nodes --all node-role.kubernetes.io/master-
```


### 4. Installing the Contiv-VPP CNI plugin
If you have already used the Contiv-VPP plugin before, you may need to pull
the most recent Docker images on each node:
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)
```

Contiv-VPP CNI plugin can be installed in two ways:
- [Contiv-VPP Helm Installation](../../k8s/README.md), allows for customization via helm options,
  but is more complex, described in [this document](../../k8s/README.md).
- YAML file based installation, easier for simple deployments, described below.

To install the Contiv-VPP CNI using the pre-generated deployment YAML:

- If you do not use the STN feature, install Contiv-VPP as follows:
  ```
  kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
  ```

- If you use the STN feature, download the `contiv-vpp.yaml` file:
  ```
  wget https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
  ```
  Then edit the STN configuration as described [here][16]. Finally, create
  the Contiv-vpp deployment from the edited file:
  ```
  kubectl apply -f ./contiv-vpp.yaml
  ```

Beware that Contiv data is persisted in `/var/etcd` on the master node by default.
It has to be cleaned up manually after `kubeadm reset`. Otherwise outdated data may
be loaded by a subsequent deployment.


## Deployment Verification
After some time, all contiv containers should enter the running state:
```
$ kubectl get pods -n kube-system -o wide
NAME                           READY     STATUS    RESTARTS   AGE       IP               NODE
contiv-etcd-gwc84              1/1       Running   0          14h       192.168.56.106   cvpp
contiv-ksr-5c2vk               1/1       Running   2          14h       192.168.56.106   cvpp
contiv-vswitch-h6759           2/2       Running   0          14h       192.168.56.105   cvpp-slave2
contiv-vswitch-l59nv           2/2       Running   0          14h       192.168.56.106   cvpp
etcd-cvpp                      1/1       Running   0          14h       192.168.56.106   cvpp
kube-apiserver-cvpp            1/1       Running   0          14h       192.168.56.106   cvpp
kube-controller-manager-cvpp   1/1       Running   0          14h       192.168.56.106   cvpp
kube-dns-545bc4bfd4-fr6j9      3/3       Running   0          14h       10.1.134.2       cvpp
kube-proxy-q8sv2               1/1       Running   0          14h       192.168.56.106   cvpp
kube-proxy-s8kv9               1/1       Running   0          14h       192.168.56.105   cvpp-slave2
kube-scheduler-cvpp            1/1       Running   0          14h       192.168.56.106   cvpp
```

In particular, make sure that the Contiv-VPP pod IP addresses are the same as
the IP address specified in the `--apiserver-advertise-address=<ip-address>`
argument to kubeadm init.

Also verify that a vswitch pod and a kube-proxy pod is running on
each joined node, as shown above.

Verify that the VPP successfully grabbed the network interface specified in
the VPP startup config (`GigabitEthernet0/9/0` in our case) on each node:
```
$ sudo vppctl
vpp# sh inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
GigabitEthernet0/9/0              1      up          9000/0/0/0     
local0                            0     down          0/0/0/0       
loop0                             2      up          9000/0/0/0     
loop1                             4      up          9000/0/0/0     
tap0                              3      up          1450/0/0/0     rx packets                   127
                                                                    rx bytes                   35767
                                                                    tx packets                    82
                                                                    tx bytes                    7714
                                                                    drops                         48
                                                                    ip4                          101
                                                                    ip6                           23
tap1                              5      up          1450/0/0/0     rx packets                    95
                                                                    rx bytes                    8764
                                                                    tx packets                    79
                                                                    tx bytes                   28989
                                                                    drops                         14
                                                                    ip4                           87
                                                                    ip6                            8
```

You should also see the interface to kube-dns / core-dns (`tap1`) and to the node's IP stack (`tap0`).


### Deploying example applications
#### Simple deployment
You can go ahead and create a simple deployment:
```
$ kubectl run nginx --image=nginx --replicas=2
```

Use `kubectl describe pod` to get the IP address of a pod, e.g.:
```
$ kubectl describe pod nginx | grep IP
```
You should see two ip addresses, for example:
```
IP:		10.1.1.3
IP:		10.1.1.4
```

You can check the pods' connectivity in one of the following ways:
* Connect to the VPP debug CLI and ping any pod:
```
  sudo vppctl
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


## Uninstalling Contiv-VPP
To uninstall the network plugin itself, use `kubectl`:
```
kubectl delete -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```
In order to remove the persisted config, cleanup the bolt and ETCD storage:
```
rm -rf /var/etcd/contiv-data
```

## Tearing down Kubernetes
* First, drain the node and make sure that the node is empty before shutting it down:
```
  kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
  kubectl delete node <node name>
```
* Next, on the node being removed, reset all kubeadm installed state:
```
  rm -rf $HOME/.kube
  sudo kubeadm reset
```


[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[3]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#initializing-your-master
[4]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#pod-network
[5]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#joining-your-nodes
[6]: https://kubernetes.io/docs/setup/independent/install-kubeadm/
[8]: #tearing-down-kubernetes
[11]: ../../vagrant/README.md
[12]: CUSTOM_MGMT_NETWORK.md
[13]: VMWARE_FUSION_HOST.md
[14]: SINGLE_NIC_SETUP.md
[15]: MULTI_NIC_SETUP.md
[16]: SINGLE_NIC_SETUP.md#configuring-stn-in-contiv-vpp-k8s-deployment-files
[17]: ../../k8s/README.md#setup-node.sh