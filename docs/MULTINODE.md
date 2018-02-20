## Multinode Deployment

For multi-node deployments, your Kubernetes nodes currently need to have at least two network interfaces:
 - one for Kubernetes management traffic (IPs used e.g. for `kubeadm join`),
 - one for data passing between PODs on different nodes, managed by DPDK and VPP. The nodes need to
 be interconnected on L2 between these interfaces.
 

### DPDK and VPP setup
In order to enable multinode POD-to-POD communication via VPP, you need to complete this 
DPDK setup **on each node**.

Load PCI UIO driver:
```
$ sudo modprobe uio_pci_generic
```

Verify it has loaded successfully:
```
$ lsmod | grep uio
uio_pci_generic        16384  0
uio                    20480  1 uio_pci_generic
```
Please note that these drivers need to be loaded upon each server bootup, so you may want to add
`uio_pci_generic` into `/etc/modules` file or a file in the `/etc/modules-load.d/` directory.

Now you need to find out the PCI address of the network interface that you want to use for multinode
POD interconnect. On Debian-based distributions, you can use `lshw`:

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
pci@0000:00:03.0  ens3        network    Virtio network device
pci@0000:00:04.0  ens4        network    Virtio network device
```

In our case, it would be the `ens4` interface with the PCI address `0000:00:04.0`.

Now, make sure that the selected interface is shut down, otherwise VPP would not grab it:
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


### Deploy the Kubernetes cluster and Contiv-VPP Network plugin
If you have your master node initialized as described in steps 1-2 in the main [README](../README.md),
you can now join your worker nodes:

```
$ sudo kubeadm join <... OUTPUT FROM KUBEADM INIT ON MASTER ...>
```

Note that if clocks are out of sync between your nodes (as may be the case with bare metal setups) then the join may fail due to "x509: certificate has expired or is not yet valid".    The best approach is probably to sync all nodes using NTP.

Verify that all nodes have successfully joined the cluster:
```
$ kubectl get nodes
NAME      STATUS     ROLES     AGE       VERSION
vm5       NotReady   master    8m        v1.8.0
vm6       NotReady   <none>    55s       v1.8.0
```

In case that a worker is not able to join, review the Troubleshooting section at the end of this document.


AFTER joining your workers, deploy the Contiv-VPP Network plugin, as described in the step 4 
in the main [README](../README.md):

```
kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```
Note: if you have already done this before the DPDK and VPP setup, undeploy the NW plugin 
(`kubectl delete -f ...`) and deploy it again.


### Verify the deployment
Verify that all components have been deployed successfully:
```
$ kubectl get pods --all-namespaces
```

On each node, verify that the VPP successfully grabbed the network interface specified 
in the VPP startup config (`GigabitEthernet0/4/0` in our case):
```
$ sudo nc -U /run/vpp/cli.sock
vpp# sh inter
              Name               Idx       State          Counter          Count     
GigabitEthernet0/4/0              1        down      
local0  
```

### Deploy PODs on different nodes
In order to verify inter-node POD connectivity, we need to tell Kubernetes to deploy
one POD on the master node and one POD on the worker. For this, we can use node selectors.

In your deployment YAMLs, add the `nodeSelector` sections that refer to preferred node hostnames, e.g.:
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

#### Troubleshooting
In case that the interface you use for Kubernetes management traffic (IPs used e.g. for `kubeadm join`)
is not the one that contains the default route out of the host, you need to configure 
and initialize Kubernetes cluster specifically.

1. Specify preferred node IP address in the Kubelet config file
(`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`):
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.101"
```
This needs to be done on each node.

2. Specify the preferred IP address of the master in `kubeadm init`:
```
sudo kubeadm init --token-ttl 0  --apiserver-advertise-address=192.168.56.101
```
