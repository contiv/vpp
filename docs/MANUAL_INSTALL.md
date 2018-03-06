## Manual Installation
This document describes hot to use [kubeadm][1] to manually install Kubernetes
with Contiv-VPP networking on one or more bare metal or VM hosts. 

### (1/4) Preparing your hosts

#### 1.0 (Optional): Prepare a VmWare Fusion host
The vmxnet3 driver is required on GigE Network Adapter used by VPP. On VmWare
Fusion, the default Network Adapter driver is Intel 82545EM (e1000), and there
is no GUI to change it to vmxnet3. The change must be done manually in the VM's
configuration file as follows:

- Bring up the VM library window: 'Window -> Virtual Machine Library'
- Right click on the VM where you want to change the driver:
  '<VM-Name> -> Show in Finder'. This pops up a new Finder window with a line
  for each VM that Fusion knows about.
- Right click on the VM where you want to change the driver:
  '<VM-Name> -> Show package contents'. This brings up a window with the 
  contents of the package.
- Open the file '<VM-Name>.vmx' with your favorite text editor
- For each Network Adapter that you want to be used by VPP, look for the 
  Network Adapter's driver configuration. For example, for the VM's first
  Network Adapter look for:
  ```
  ethernet0.virtualDev = "e1000"
  ```
  Replace `e1000` with `vmxnet3`:
  ```
  ethernet0.virtualDev = "vmxnet3"
  ```
and restart the VM.

If you replaced the driver on your VM's primary Network Adapter, you will 
have to change the primary network interface configuration in Linux. First,
get the new primary network interface name:
```
sudo lshw -class network -businfo

Bus info          Device      Class          Description
========================================================
pci@0000:03:00.0  ens160      network        VMXNET3 Ethernet Controller
```
Replace the existing primary network interface name in `/etc/network/interfaces`
with the above device name:
```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ens160
iface ens160 inet dhcp
```

#### 1.1: Installing kubeadm on your hosts
For first-time installation, see [Installing kubeadm][6]. To update an
existing installation,  you should do a `apt-get update && apt-get upgrade`
or `yum update` to get the latest version of kubeadm.

#### 1.2 (Optional): Setting up DPDK and VPP in multi-node deployments
In order to enable multinode pod-to-pod communication via VPP, you need to
complete this DPDK setup **on each node**.

Load the PCI UIO driver:
```
$ sudo modprobe uio_pci_generic
```

Verify that the PCI UIO driver has loaded successfully:
```
$ lsmod | grep uio
uio_pci_generic        16384  0
uio                    20480  1 uio_pci_generic
```
Please note that this driver needs to be loaded upon each server bootup, so
you may want to add `uio_pci_generic` into the `/etc/modules` file, or a file
in the `/etc/modules-load.d/` directory. For example, the `/etc/modules` file
could look as follows:
```
# /etc/modules: kernel modules to load at boot time.
#
# This file contains the names of kernel modules that should be loaded
# at boot time, one per line. Lines beginning with "#" are ignored.
uio_pci_generic
```

Now you need to find out the PCI address of the network interface that
you want VPP to use for multi-node pod interconnect. On Debian-based
distributions, you can use `lshw`:

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
pci@0000:00:03.0  ens3        network    Virtio network device
pci@0000:00:04.0  ens4        network    Virtio network device
```

In our case, it would be the `ens4` interface with the PCI address
`0000:00:04.0`.

Now, make sure that the selected interface is shut down, otherwise VPP
would not grab it:
```
sudo ip link set ens4 down
```

Now, add, or modify the VPP startup config file in `/etc/vpp/contiv-vswitch.conf`
to contain the proper PCI address:
```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    cli-no-pager
}
dpdk {
    dev 0000:00:04.0
}
```
#### 1.3 (Optional): Setting up custom management network on multi-homed nodes
If the interface you use for Kubernetes management traffic (for example, the
IP address used for `kubeadm join`) is not the one that contains the default
route out of the host, you need to specify the management node IP address in
the Kubelet config file. Add the following line to
(`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`):
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=<node-management-ip-address>"
```
##### Example:
Consider a 2 node deployment where each node is connected to 2 networks -
`10.0.2.0/24` and `192.168.56.0/24`, and the default route on each node points
to the interface connected to the `10.0.2.0/24` subnet. We want to use subnet
`192.168.56.0/24` for Kubernetes management traffic. Assume the addresses of
nodes connected to `192.168.56.0/24` are `192.168.56.105` and `192.168.56.106`.

On the `192.168.56.105` node you add the following line to `10-kubeadm.conf`:
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.105"
```
On the `192.168.56.106` node you add the following line to `10-kubeadm.conf`:
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.106"
```

#### 1.4 (Optional): Installing the STN daemon on your hosts
If you plan to use the "Steal the NIC" feature (STN), for deployments
on nodes with just single network interface, you must first install the
STN daemon on each host of the k8s cluster. The STN daemon installation
should be performed before deployment of the Contiv-VPP plugin.

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```

#### 1.5 (Optional): Installing the CRI Shim on your hosts
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

The steps 1.2 - 1.5 can be set up interactively using [script](../k8s/setup-node.sh).
```
bash <(curl https://raw.githubusercontent.com/contiv/vpp/master/k8s/setup-node.sh)
```

### (2/4) Initializing your master
Before initializing the master, you may want to [tear down][8] up any
previously installed K8s components. Then, proceed with master initialization
as described in the [kubeadm manual][3]. Execute the following command as
root:
```
kubeadm init --token-ttl 0
```
Note that the above command will autodetect the network interface to advertise
the master on as the interface with the default gateway. If you want to use a
different interface (i.e. a custom management network setup), specify the
`--apiserver-advertise-address=<ip-address>` argument to kubeadm init. For
example:
```
kubeadm init --token-ttl 0  --apiserver-advertise-address=192.168.56.106
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
If you have already used the Contiv-VPP plugin before, you may need to pull
the most recent Docker images on each node:
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)
```

Install the Contiv-VPP network for your cluster as follows:
```
kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
root@cvpp:/home/jan# kubectl get pods -n kube-system -o wide | grep contiv
NAME                           READY     STATUS    RESTARTS   AGE       IP               NODE
...
contiv-etcd-gwc84              1/1       Running   0          14h       192.168.56.106   cvpp
contiv-ksr-5c2vk               1/1       Running   2          14h       192.168.56.106   cvpp
contiv-vswitch-l59nv           2/2       Running   0          14h       192.168.56.106   cvpp
```
In particular, make sure that the Contiv-VPP pod IP addresses are the same as
the IP address specified in the `--apiserver-advertise-address=<ip-address>`
argument to kubeadm init.

Verify that the VPP successfully grabbed the network interface specified in
the VPP startup config (`GigabitEthernet0/4/0` in our case):
```
$ sudo nc -U /run/vpp/cli.sock
vpp# sh inter
              Name               Idx       State          Counter          Count
GigabitEthernet0/4/0              1         up       rx packets                  1294
                                                     rx bytes                  153850
                                                     tx packets                   512
                                                     tx bytes                   21896
                                                     drops                        962
                                                     ip4                         1032
host-40df9b44c3d42f4              3         up       rx packets                126601
                                                     rx bytes                44628849
                                                     tx packets                132155
                                                     tx bytes                27205450
                                                     drops                         24
                                                     ip4                       126585
                                                     ip6                           16
host-vppv2                        2         up       rx packets                132162
                                                     rx bytes                27205824
                                                     tx packets                126658
                                                     tx bytes                44634963
                                                     drops                         15
                                                     ip4                       132147
                                                     ip6                           14
local0                            0        down
```

You should also see the interface to kube-dns (`host-40df9b44c3d42f4`) and to the
node's IP stack (`host-vppv2`).

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
More details can be found int the [kubeadm manual][5].

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
root@cvpp:/home/jan# kubectl get pods -n kube-system -o wide | grep contiv
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
In particular, verify that a vswitch pod and a kube-proxy pod is running on
each joined node, as shown above.

On each joined node, verify that the VPP successfully grabbed the network
interface specified in the VPP startup config (`GigabitEthernet0/4/0` in
our case):
```
$ sudo nc -U /run/vpp/cli.sock
vpp# sh inter
              Name               Idx       State          Counter          Count
GigabitEthernet0/4/0              1         up
...
```
From the vpp CLI on a joined node you can also ping kube-dns to verify
node-to-node connectivity. For example:
```apple js
vpp# ping 10.1.134.2
64 bytes from 10.1.134.2: icmp_seq=1 ttl=64 time=.1557 ms
64 bytes from 10.1.134.2: icmp_seq=2 ttl=64 time=.1339 ms
64 bytes from 10.1.134.2: icmp_seq=3 ttl=64 time=.1295 ms
64 bytes from 10.1.134.2: icmp_seq=4 ttl=64 time=.1714 ms
64 bytes from 10.1.134.2: icmp_seq=5 ttl=64 time=.1317 ms

Statistics: 5 sent, 5 received, 0% packet loss
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
IP:		10.1.1.3
IP:		10.1.1.4
```

You can check the pods' connectivity in one of the following ways:
* Connect to the VPP debug CLI and ping any pod:
```
  sudo nc -U /run/vpp/cli.sock
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

#### Deploying pods on different nodes
to enable pod deployment on the master, untaint the master first:
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

### Uninstalling Contiv-VPP
To uninstall the network plugin itself, use `kubectl`:
```
kubectl delete -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```

To uninstall the CRI shim, execute as root (not using sudo) on each node:
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh) --uninstall
```

After uninstalling CRI, reboot each node, or re-initialize the Kubernetes
cluster using `kubeadm reset` and `kubeadm init --token-ttl 0`.

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
   [Step 1.3][10]), clean them up now.


* If you installed the CRI Shim as instructed in [Step 1.4][9], uninstall it now:
```
  bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh) --uninstall
```

### Tearing down Kubernetes
You should first drain the node and make sure that the node is empty before
shutting it down:
```
kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
kubectl delete node <node name>
```
Then, on the node being removed, reset all kubeadm installed state:
```
rm -rf $HOME/.kube
sudo su
kubeadm reset
```

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
```

[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[2]: https://kubernetes.io/docs/setup/independent/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl
[3]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#initializing-your-master
[4]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#pod-network
[5]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#joining-your-nodes
[6]: https://kubernetes.io/docs/setup/independent/install-kubeadm/
[7]: MULTINODE.md
[8]: #tear-down
[9]: #installing-the-cri-shim-on-your-hosts
[10]: #setting-up-custom-management-network-on-multi-homed-nodes
[11]: ../vagrant/README.md
