# Manual Installation On Cavium Thunderx
This document describes how to use [kubeadm][1] to manually install Kubernetes
with Contiv-VPP networking on one or more Cavium ThunderX bare metal machines
provided by [packet][18].

## Preparing your hosts

### Host-specific configuration
* Packet’s Cavium Thunderx's are using [bonded network configuration][20] by default. Kubernetes with Contiv-VPP doesn't support bonding, which needs to be removed.

  WARNING:
  Disabling bonding will remove public connectivity from your server
  and you will have to use [SOS][23] to connect.
  QUESTION: can

* Configure the network according to [Packet's l2 configuation instruction][19] - section "C #3: Using eth0 with a publicly-connected VLAN and eth1 on a private VLAN".

* [Install docker][36].

* Check the drivers used on the host according to [34.6.1. SR-IOV: Prerequisites and sample Application Notes][30].

    * In particular, verify PF and VF device capabilities

* Check that drivers are loadable by looking for CONFIG_THUNDER_NIC in your boot config:
  ```
  $ grep CONFIG_THUNDER_NIC /boot/config-$(uname -r)
  CONFIG_THUNDER_NIC_PF=m
  CONFIG_THUNDER_NIC_VF=m
  CONFIG_THUNDER_NIC_BGX=m
  CONFIG_THUNDER_NIC_RGX=m
  ```

### Setting up Network Adapter(s)
#### Setting up DPDK
DPDK setup must be set up **on each node** as follows:

- Load the VFIO PCI driver:
  ```
  $ sudo modprobe vfio-pci
  ```

- Verify that the VFIO PCI driver has loaded successfully:
  ```
  $ lsmod | grep vfio_pci
  vfio_pci               49152  1
  vfio_virqfd            16384  1 vfio_pci
  vfio                   40960  6 vfio_iommu_type1,vfio_pci
  ```

  Please note that this driver needs to be loaded upon each server bootup,
  so you may want to add `vfio_pci` into the `/etc/modules` file,
  or a file in the `/etc/modules-load.d/` directory. For example, the
  `/etc/modules` file could look as follows:
  ```
  # /etc/modules: kernel modules to load at boot time.
  #
  # This file contains the names of kernel modules that should be loaded
  # at boot time, one per line. Lines beginning with "#" are ignored.
  vfio-pci
  ```
#### Determining Network Adapter PCI addresses
You need to find out the PCI address of the network interface that
you want VPP to use for multi-node pod interconnect. On Debian-based
distributions, you can use `lshw`(*):
 ```
 $ sudo lshw -class network -businfo
 Bus info          Device      Class      Description
 ====================================================
 pci@0000:01:10.0              network    THUNDERX BGX (Common Ethernet Interface)
 pci@0002:01:00.0              network    THUNDERX Network Interface Controller
 pci@0002:01:00.1  enP2p1s0f1  network    Illegal Vendor ID
 pci@0002:01:00.2  enP2p1s0f2  network    Illegal Vendor ID
 pci@0002:01:00.3              network    Illegal Vendor ID
 pci@0002:01:00.4              network    Illegal Vendor ID
 pci@0002:01:00.5              network    Illegal Vendor ID
 pci@0002:01:00.6              network    Illegal Vendor ID
 pci@0002:01:00.7              network    Illegal Vendor ID
 pci@0002:01:01.0              network    Illegal Vendor ID
 pci@0002:01:01.1              network    Illegal Vendor ID
 pci@0002:01:01.2              network    Illegal Vendor ID
 pci@0002:01:01.3              network    Illegal Vendor ID
 pci@0002:01:01.4              network    Illegal Vendor ID
 pci@0002:01:01.5              network    Illegal Vendor ID
 pci@0002:01:01.6              network    Illegal Vendor ID
 pci@0002:01:01.7              network    Illegal Vendor ID
 pci@0002:01:02.0              network    Illegal Vendor ID
 pci@0002:01:02.1              network    Illegal Vendor ID
 pci@0002:01:02.2              network    Illegal Vendor ID
 pci@0002:01:02.3              network    Illegal Vendor ID
 pci@0002:01:02.4              network    Illegal Vendor ID
 pci@0002:01:02.5              network    Illegal Vendor ID
 pci@0002:01:02.6              network    Illegal Vendor ID
 pci@0002:01:02.7              network    Illegal Vendor ID
 pci@0002:01:03.0              network    Illegal Vendor ID
 pci@0002:00:03.0              network    THUNDERX Traffic Network Switch
 pci@0006:01:00.0              network    THUNDERX Network Interface Controller
 pci@0006:00:03.0              network    THUNDERX Traffic Network Switch
 ```
\* On CentOS/RedHat/Fedora distributions, `lshw` may not be available by default, install it by
    ```
    yum -y install lshw
    ```

Notice that the previous command lists a lot of items.
The reason is that the built-in NIC found in the Cavium ThunderX SoC family
is a card with [SR-IOV][29] virtual functions (VF).

#### Customization on the target machine
To use this card (COMMENT: which card?) in context of Kubernetes with Contiv-VPP network plugin
there is the need to follow instructions at [the DPDK pages - Linux prerequisites][31]:
(COMMENT: are we duplicating what's on the DPDK page? If so, we don't need to link to it, since it's just going to confuse people, like it confused me)
Required Kernel version >= 3.2

This manual describes the successful deployment on a Ubuntu 18.04.1 LTS
Kubernetes master node with 4.15.0-20-generic Linux kernel and a Ubuntu 16.04.5 LTS
Kubernetes slave node with 4.10.0-38-generic Linux kernel.

* glibc >= 2.7 (for features related to cpuset). The version can be checked using the ldd --version command.
  ```
  COMMENT: Ubuntu 16.04 has this version, should we specify how to update it?
  $ ldd --version
  ldd (Ubuntu GLIBC 2.23-0ubuntu10) 2.23
  ```
* kernel configuration
  ```
  $ cat /boot/config-4.10.0-38-generic | grep HUGETLBFS
  CONFIG_SYS_SUPPORTS_HUGETLBFS=y
  CONFIG_HUGETLBFS=y
  $ cat /boot/config-4.10.0-38-generic | grep PROC_PAGE_MONITOR
  CONFIG_PROC_PAGE_MONITOR=y
  $ cat /boot/config-4.10.0-38-generic | grep HPET
  # CONFIG_HPET is not set
  ```
  HUGETLBFS option must be enabled in the running kernel

  The allocation of hugepages should be done at boot time or as soon as possible after system boot to prevent memory from being fragmented in physical memory. To reserve hugepages at boot time, a parameter is passed to the Linux kernel on the kernel command line. Add these parameters to the file /etc/default/grub:
  ```
  COMMENT: this is confusing, later we're working with 16 hugepages, let's make it consistent
  default_hugepagesz=1G hugepagesz=1G hugepages=4
  ```

  For Ubuntu 18.04 you need also to add the parameter iommu.passthrough=1 to the file /etc/default/grub according this [webpage][32].

  The file /etc/default/grub should look like this:
  ```
  GRUB_DEFAULT=0
  #GRUB_HIDDEN_TIMEOUT=0
  GRUB_HIDDEN_TIMEOUT_QUIET=true
  GRUB_TIMEOUT=10
  GRUB_DISTRIBUTOR=Ubuntu
  GRUB_CMDLINE_LINUX="console=ttyAMA0,115200n8 biosdevname=0 net.ifnames=1 crashkernel=auto LANG=en_US.UTF-8 iommu.passthrough=1 hugepagesz=1GB hugepages=16 default_hugepagesz=1GB iomem=relaxed"
  GRUB_TERMINAL=serial
  GRUB_SERIAL_COMMAND="serial"
  ```

  Once the hugepage memory is reserved, to make the memory available for DPDK use, perform the following steps:
  ```
  mkdir /mnt/huge
  mount -t hugetlbfs nodev /mnt/huge_1GB pagesize=1GB
  ```
  or add this line to /etc/fstab file to make the mount point permanent across reboots
  ```
  nodev /mnt/huge_1GB hugetlbfs pagesize=1GB 0 0
  ```

  You can check memory allocation:
  ```
  $ grep "Huge" /proc/meminfo
  AnonHugePages:         0 kB
  ShmemHugePages:        0 kB
  HugePages_Total:      16
  HugePages_Free:       11
  HugePages_Rsvd:        0
  HugePages_Surp:        0
  Hugepagesize:    1048576 kB
  ```

#### Setting up the vswitch to use Network Adapters
Finally, you need to set up the vswitch to use the network adapters:

- [Setup a node with multiple NICs][35]


## Installing Kubernetes with Contiv-vpp CNI plugin
After the nodes have been configured, you can install the cluster using [kubeadm][1].

### (1/4) Installing Kubeadm on your hosts
For first-time installation, see [Installing kubeadm][6]. To update an
existing installation,  you should do a `apt-get update && apt-get upgrade`
or `yum update` to get the latest version of kubeadm.

On each host with multiple NICs where the NIC that will be used for Kubernetes
management traffic is not the one pointed to by the default route out of the
host, a [custom management network][12] for Kubernetes must be configured.

#### Using Kubernetes 1.10 and above
In K8s 1.10, support for huge pages in a pod has been introduced. For now, this
feature must be either disabled or memory limit must be defined for vswitch container.

This case was successfully tested:
To define memory limit, append the following snippet to vswitch container in deployment yaml file:
```
          resources:
            limits:
              hugepages-1Gi: 8Gi
              memory: 8Gi
```
or set `contiv.vswitch.defineMemoryLimits` to `true` in [helm values](../k8s/contiv-vpp/README.md).

### (2/4) Initializing your master
Before initializing the master, you may want to [tear down][8] up any
previously installed K8s components. Then, proceed with master initialization
as described in the [kubeadm manual][3]. Execute the following command as
root:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16
```
**Note:** `kubeadm init` will autodetect the network interface associated with
default gateway to advertise the master's IP. If you want to use a
different interface (i.e. a custom management network setup), specify the
`--apiserver-advertise-address=<ip-address>` argument to kubeadm init. For
example:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16 --apiserver-advertise-address=192.168.56.106
```
**Note:** The CIDR specified with the flag `--pod-network-cidr` is used by
kube-proxy, and it **must include** the `PodSubnetCIDR` from the `IPAMConfig`
section in the Contiv-vpp config map in Contiv-vpp's deployment file
([contiv-vpp.yaml](../k8s/contiv-vpp.yaml)). Pods in the host network namespace
are a special case; they share their respective interfaces and IP addresses with
the host. For proxying to work properly it is therefore required for services
with backends running on the host to also **include the node management IP**
within the `--pod-network-cidr` subnet. For example, with the default
`PodSubnetCIDR=10.1.0.0/16` and `PodIfIPCIDR=10.2.1.0/24`, the subnet
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

After successful initialization, don't forget to set up your .kube directory
as a regular user (as instructed by `kubeadm`):
```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

### (3/4) Installing the Contiv-VPP pod network
Install the Contiv-VPP network for your cluster as follows:

- If you do not use the STN feature, install Contiv-vpp as follows:
  ```
  kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-arm64.yaml
  ```

- If you use the STN feature, download the `contiv-vpp.yaml` file:
  ```
  wget https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-arm64.yaml
  ```
  Then edit the STN configuration as described [here][16]. Finally, create
  the Contiv-vpp deployment from the edited file:
  ```
  kubectl apply -f ./contiv-vpp-arm64.yaml
  ```

Beware contiv-etcd data is persisted in `/var/etcd` by default. It has to be cleaned up manually after `kubeadm reset`.
Otherwise outdated data will be loaded by a subsequent deployment.

You can also generate random subfolder, alternatively:

```
curl --silent https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-arm64.yaml | sed "s/\/var\/etcd\/contiv-data/\/var\/etcd\/contiv-data\/$RANDOM/g" | kubectl apply -f -
```

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
$ kubectl get pods -n kube-system -o wide | grep contiv
NAME                                             READY     STATUS    RESTARTS   AGE       IP              NODE
contiv-etcd-0                                    1/1       Running   0          1d        147.75.98.202   cvpp
contiv-ksr-4pw9s                                 1/1       Running   0          1d        147.75.98.202   cvpp
contiv-vswitch-ptx7n                             1/1       Running   0          1d        147.75.98.202   cvpp
```
In particular, make sure that the Contiv-VPP pod IP addresses are the same as
the IP address specified in the `--apiserver-advertise-address=<ip-address>`
argument to kubeadm init.

Verify that the VPP successfully grabbed the network interface specified in
the VPP startup config (`VirtualFunctionEthernet1/0/2` in our case):
```
$ docker exec -it  `docker ps | grep "\/usr\/bin\/supervisor" | cut --delimiter=" " --fields=1` /usr/bin/vppctl
    _______    _        _   _____  ___
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/

vpp# show interface
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
VirtualFunctionEthernet1/0/2      1      up          9000/0/0/0     rx packets                  1031
                                                                    rx bytes                   66879
                                                                    tx packets                  1043
                                                                    tx bytes                   58887
                                                                    drops                        498
                                                                    ip4                           52
                                                                    tx-error                       1
local0                            0     down          0/0/0/0
loop0                             3      up          9000/0/0/0     rx packets                    47
                                                                    rx bytes                    4641
                                                                    tx packets                   118
                                                                    tx bytes                   11226
                                                                    drops                         16
                                                                    ip4                           47
tap0                              2      up          1500/0/0/0     rx packets                291928
                                                                    rx bytes               106499985
                                                                    tx packets                214364
                                                                    tx bytes                17420543
                                                                    drops                        780
                                                                    ip4                       291148
                                                                    ip6                           39
tap1                              5      up          1500/0/0/0     rx packets                106880
                                                                    rx bytes                 8700437
                                                                    tx packets                146750
                                                                    tx bytes                53313139
                                                                    drops                         60
                                                                    ip4                       106841
                                                                    ip6                           39
tap2                              6      up          1500/0/0/0     rx packets                106877
                                                                    rx bytes                 8700012
                                                                    tx packets                144447
                                                                    tx bytes                53157700
                                                                    drops                         51
                                                                    ip4                       106839
                                                                    ip6                           38
vpp# show interface addr
VirtualFunctionEthernet1/0/2 (up):
  L3 192.168.16.1/24
local0 (dn):
loop0 (up):
  L2 bridge bd-id 2 idx 2 shg 1 bvi
  L3 192.168.30.1/24
tap0 (up):
  L3 172.30.1.1/24
tap1 (up):
  L3 10.2.1.2/32
tap2 (up):
  L3 10.2.1.3/32
vpp#

```

You should also see the interface to kube-dns (`tap1` and `tap2`) and to the
node's IP stack (`tap0`).

#### Master Isolation (Optional)
By default, your cluster will not schedule pods on the master for security
reasons. If you want to be able to schedule pods on the master, e.g. for a
single-machine Kubernetes cluster for development, run:

```
kubectl taint nodes --all node-role.kubernetes.io/master-
```
More details about installing the pod network can be found in the
[kubeadm manual][4].

### (4/4) Joining your nodes
To add a new node to your cluster, run as root the command that was output
by kubeadm init. For example:
```
kubeadm join --token <token> <master-ip>:<master-port> --discovery-token-ca-cert-hash sha256:<hash>
```
After starting kubernetes you can look at how a join command looks like:
```
$ sudo kubeadm token create --print-join-command
kubeadm join 147.75.98.202:6443 --token v7qx7g.dkiy12lxt6sd534q --discovery-token-ca-cert-hash sha256:73e924e696ddb0a7016d7e70053b46664ab5361b3b8e6099cb55dadaa202fd67
```
More details can be found in the [kubeadm manual][5].

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
$ kubectl get pods -n kube-system -o wide
NAME                                             READY     STATUS    RESTARTS   AGE       IP              NODE
contiv-etcd-0                                    1/1       Running   0          1d        147.75.98.202   cvpp
contiv-ksr-4pw9s                                 1/1       Running   0          1d        147.75.98.202   cvpp
contiv-vswitch-ptx7n                             1/1       Running   0          1d        147.75.98.202   cvpp
contiv-vswitch-rvh8p                             1/1       Running   0          14s       147.75.72.194   cvpp-slave2
coredns-78fcdf6894-lvcj4                         1/1       Running   0          1d        10.1.1.2        cvpp
coredns-78fcdf6894-tsxhl                         1/1       Running   0          1d        10.1.1.3        cvpp
etcd-cvpp                                        1/1       Running   0          1d        147.75.98.202   cvpp
kube-apiserver-cvpp                              1/1       Running   0          1d        147.75.98.202   cvpp
kube-controller-manager-cvpp                     1/1       Running   0          1d        147.75.98.202   cvpp
kube-proxy-8dfjz                                 1/1       Running   0          14s       147.75.72.194   cvpp-slave2
kube-proxy-9p6rq                                 1/1       Running   0          1d        147.75.98.202   cvpp
kube-scheduler-cvp                               1/1       Running   0          1d        147.75.98.202   cvpp
```
In particular, verify that a vswitch pod and a kube-proxy pod is running on
each joined node, as shown above.

On each joined node, verify that the VPP successfully grabbed the network
interface specified in the VPP startup config (`VirtualFunctionEthernet1/0/2` in
our case):
```
$ docker exec -it  `docker ps | grep "\/usr\/bin\/supervisor" | cut --delimiter=" " --fields=1` /usr/bin/vppctl
...
vpp# show interface
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
VirtualFunctionEthernet1/0/2      1      up          9000/0/0/0     rx packets                  1031
...
```
You can also ping coredns from VPP on a joined node to verify
node-to-node connectivity. For example:
```apple js
vpp# ping 10.1.1.2
64 bytes from 10.1.1.2: icmp_seq=2 ttl=63 time=.9912 ms
64 bytes from 10.1.1.2: icmp_seq=3 ttl=63 time=.7172 ms
64 bytes from 10.1.1.2: icmp_seq=4 ttl=63 time=.7189 ms
64 bytes from 10.1.1.2: icmp_seq=5 ttl=63 time=.8852 ms

Statistics: 5 sent, 4 received, 20% packet loss
vpp#
```
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
IP:                 10.1.1.7
IP:                 10.1.1.8
```
Note: You can find these IP addresses also issuing command `kubectl get pods -o wide`

You can check the pods' connectivity in one of the following ways:
* Connect to the VPP debug CLI and ping any pod:
```
  sudo vppctl
  vpp# ping 10.1.1.7
```
* Start busybox and ping any pod:
```
  kubectl run busybox --rm -ti --image=busybox /bin/sh
  If you don't see a command prompt, try pressing enter.
  / #
  / # ping 10.1.1.7

```
* You should be able to ping any pod from the host:
```
  ping 10.1.1.7
```

#### Deploying pods on different nodes
To enable pod deployment on the master, untaint the master first:
```
kubectl taint nodes --all node-role.kubernetes.io/master-
```

In order to verify inter-node pod connectivity, we need to tell Kubernetes
to deploy one pod on the master node and one POD on the worker. For this,
we can use node selectors.

In your deployment YAMLs, add the `nodeSelector` sections that refer to
preferred node hostnames, e.g.:
```
  nodeSelector:
    kubernetes.io/hostname: vm5
```

Example of whole JSONs:
```
apiVersion: v1
kind: Pod
metadata:
  name: nginx1
spec:
  nodeSelector:
    kubernetes.io/hostname: vm5
  containers:
    - name: nginx
      image: nginx
```

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx2
spec:
  nodeSelector:
    kubernetes.io/hostname: vm6
  containers:
    - name: nginx
      image: nginx
```

After deploying the JSONs, verify they were deployed on different hosts:
```
$ kubectl get pods -o wide
NAME      READY     STATUS    RESTARTS   AGE       IP           NODE
nginx1    1/1       Running   0          13m       10.1.36.2    vm5
nginx2    1/1       Running   0          13m       10.1.219.3   vm6
```

Now you can verify the connectivity to both nginx PODs from a busybox POD:
```
kubectl run busybox --rm -it --image=busybox /bin/sh

/ # wget 10.1.36.2
Connecting to 10.1.36.2 (10.1.36.2:80)
index.html           100% |*******************************************************************************************************************************************************************|   612   0:00:00 ETA

/ # rm index.html

/ # wget 10.1.219.3
Connecting to 10.1.219.3 (10.1.219.3:80)
index.html           100% |*******************************************************************************************************************************************************************|   612   0:00:00 ETA
```

Or try redeployment like this:
```
$ kubectl scale --current-replicas=2 --replicas=4 deployment/nginx
deployment.extensions/nginx scaled
$ kubectl get pods -o wide
NAME                     READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-64f497f8fd-2cjfv   1/1       Running   0          14s       10.1.2.2   cvpp-slave2
nginx-64f497f8fd-gmk55   1/1       Running   0          34m       10.1.1.7   cvpp
nginx-64f497f8fd-j5q4b   1/1       Running   0          34m       10.1.1.8   cvpp
nginx-64f497f8fd-sv6bh   1/1       Running   0          14s       10.1.2.3   cvpp-slave2

```
Then verify how describe above...
COMMENT: what is this? ^^

Note:
To delete the deployment, issue the commnad `kubectl delete deployment/nginx`

### Uninstalling Contiv-VPP
To uninstall the network plugin itself, use `kubectl`:
```
kubectl delete -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-arm64.yaml
```

### Tearing down Kubernetes
* First, drain the node and make sure that the node is empty before
shutting it down:
```
  kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
  kubectl delete node <node name>
```
* Next, on the node being removed, reset all kubeadm installed state:
```
  rm -rf $HOME/.kube
  sudo su
  kubeadm reset
```

* If you added environment variable definitions into
  `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` (e.g. in
   [Step 1/4][10]), clean them up now.

### Troubleshooting
Some of the issues that can occur during the installation are:

- Forgetting to create and initialize the `.kube` directory in your home
  directory (As instructed by `kubeadm init --token-ttl 0`). This can manifest
  itself as the following error:
  ```
  W1017 09:25:43.403159    2233 factory_object_mapping.go:423] Failed to download OpenAPI (Get https://192.168.209.128:6443/swagger-2.0.0.pb-v1: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")), falling back to swagger
  Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")
  ```
- Previous installation lingering on the file system.
  `'kubeadm init --token-ttl 0` fails to initialize kubelet with one or more
  of the following error messages:
  ```
  ...
  [kubelet-check] It seems like the kubelet isn't running or healthy.
  [kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10255/healthz' failed with error: Get http://localhost:10255/healthz: dial tcp [::1]:10255: getsockopt: connection refused.
  ...
  ```

If you run into any of the above issues, try to clean up and reinstall as root:
```
sudo su
rm -rf $HOME/.kube
kubeadm reset
kubeadm init --token-ttl 0
rm -rf /var/etcd/contiv-data
```

[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[3]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#initializing-your-master
[4]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#pod-network
[5]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#joining-your-nodes
[6]: https://kubernetes.io/docs/setup/independent/install-kubeadm/
[8]: #tearing-down-kubernetes
[10]: #14-installing-kubeadm-on-your-hosts
[11]: ../vagrant/README.md
[12]: CUSTOM_MGMT_NETWORK.md
[13]: VMWARE_FUSION_HOST.md
[14]: SINGLE_NIC_SETUP.md
[15]: MULTI_NIC_SETUP.md
[16]: SINGLE_NIC_SETUP.md#configuring-stn-in-contiv-vpp-k8s-deployment-files
[17]: ../k8s/README.md#setup-node-sh
[18]: https://www.packet.net/bare-metal/servers/c1-large-arm/
[19]: https://help.packet.net/technical/networking/layer-2-configurations
[20]: https://help.packet.net/technical/networking/lacp-bonding
[23]: https://help.packet.net/technical/networking/sos-serial-over-ssh
[24]: https://hub.docker.com/r/stanislavchlebec/vswitch-arm64/tags/
[25]: https://github.com/coreos/etcd/blob/17be3b551a0b8b8335dade33154fa2267527e377/Documentation/op-guide/supported-platform.md
[26]: https://quay.io/repository/coreos/etcd?tag=latest&tab=tags
[27]: https://help.packet.net/technical/networking/layer-2-configurations
[28]: https://help.packet.net/technical/networking/layer-2-overview
[29]: https://blog.scottlowe.org/2009/12/02/what-is-sr-iov/
[30]: https://doc.dpdk.org/guides/nics/thunderx.html#sr-iov-prerequisites-and-sample-application-notes
[31]: https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#running-dpdk-applications
[32]: https://certification.ubuntu.com/hardware/201609-25110/
[35]: MULTI_NIC_SETUP_CAVIUM.md
[36]: https://help.packet.net/hardware/arm/docker-on-arm
