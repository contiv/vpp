# Enabling IPv6 in Contiv-VPP


## Host prerequisites

- Each Kubernetes host must have an IPv6 address that is reachable from the other hosts.
- Each host must have the sysctl setting `net.ipv6.conf.all.forwarding` set to `1`. 
- Each host must have a default IPv6 route pointing to the interface used for interconnecting
  the nodes.


## Setup

Please follow the [MANUAL INSTALL](MANUAL_INSTALL.md) document with the following changes / extensions:

### In Step: 1. Preparing the nodes
Enable IPv6 forwarding on each node:
```
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

If it does not already exists in your deployment, configure an interface with an IPv6 address 
(used for interconnecting the nodes) and add an IPv6 default route pointing to that interface:
```
# this is just an example - the interface name, IPv6 address 
# and the gateway IPv6 address will be different in your deployment

sudo ip -6 address add fd00::101/64 dev enp0s9
sudo ip -6 route add default via fd00::1 dev enp0s9
```

### In Step: 2 Installing & intializing Kubernetes (using kubeadm)
In case your nodes have multiple network interfaces, or are working in a dual-stack
setup (both IPv4 or IPv6 addresses), it is necessary to tell k8s which IP address
it should use as the management IP. 

Before initializing your cluster, add the IPv6 management address into
the `/etc/default/kubelet` file, e.g.:
```
KUBELET_EXTRA_ARGS=--node-ip=fd00::101
```

Then restart kubelet, e.g.:
```
sudo service kubelet restart
```

When initializing your master using `kubeadm init`, it is necessary to specify desired IPv6
addresses into `--apiserver-advertise-address` (the IPv6 management address of the master),
`--pod-network-cidr` (subnet for PODs within all nodes) and `--service-cidr`
(ClusterIP service range), e.g.:

```
sudo kubeadm init --apiserver-advertise-address=fd00::101 --pod-network-cidr=2001::/48 --service-cidr=2096::/110
```

### In Step: 4. Installing the Contiv-VPP CNI plugin

If you are installing Contiv-VPP using the pre-generated YAML files, modify the `ipamConfig`
section to contain desired IPv6 addresses. Also add `serviceCIDR` with desired service range 
into this section. E.g.:

```yaml
    ipamConfig:
      nodeInterconnectDHCP: false
      nodeInterconnectCIDR: fe10:f00d::/90
      podSubnetCIDR: 2001::/48
      podSubnetOneNodePrefixLen: 64
      vppHostSubnetCIDR: 2002::/64
      vppHostSubnetOneNodePrefixLen: 112
      vxlanCIDR: 2005::/112
      serviceCIDR: 2096::/110
```

Make sure that `podSubnetCIDR` and `serviceCIDR` match with what you passed
into `kubeadm init` in the previous step.

If you are installing Contiv-VPP via [Helm](../../k8s/contiv-vpp/README.md),
you can pass the the above mentioned IPAM setting as helm options, e.g.:
```
--set contiv.ipamConfig.nodeInterconnectCIDR=fe10:f00d::/90
--set contiv.ipamConfig.podSubnetCIDR=2001::/48 --set contiv.ipamConfig.podSubnetOneNodePrefixLen=64
--set contiv.ipamConfig.vppHostSubnetCIDR=2002::/64 --set contiv.ipamConfig.vppHostSubnetOneNodePrefixLen=112
--set contiv.ipamConfig.vxlanCIDR=2005::/112 --set contiv.ipamConfig.serviceCIDR=2096::/110
```


## Deployment Verification
After some time, all PODs should enter the running state. All PODs should have an IPv6 address
assigned (host network PODs display the node management IP, other PODs IP from the POD CIDR):
```
$ kubectl get pods --all-namespaces -o wide
NAMESPACE     NAME                               READY     STATUS             RESTARTS   AGE       IP              NODE
kube-system   contiv-crd-lnh97                   1/1       Running            0          51s       fd00::101       ubuntu-1
kube-system   contiv-etcd-0                      1/1       Running            0          53s       fd00::101       ubuntu-1
kube-system   contiv-ksr-psrjs                   1/1       Running            0          51s       fd00::101       ubuntu-1
kube-system   contiv-vswitch-bzfcw               1/1       Running            0          53s       fd00::101       ubuntu-1
kube-system   coredns-86c58d9df4-ds8wp           1/1       Running            0          15m       2001:0:0:1::3   ubuntu-1
kube-system   coredns-86c58d9df4-zdlhj           1/1       Running            0          15m       2001:0:0:1::2   ubuntu-1
kube-system   etcd-ubuntu-1                      1/1       Running            0          14m       fd00::101       ubuntu-1
kube-system   kube-apiserver-ubuntu-1            1/1       Running            0          15m       fd00::101       ubuntu-1
kube-system   kube-controller-manager-ubuntu-1   1/1       Running            0          15m       fd00::101       ubuntu-1
kube-system   kube-proxy-28gg7                   1/1       Running            0          15m       fd00::101       ubuntu-1
kube-system   kube-scheduler-ubuntu-1            1/1       Running            0          15m       fd00::101       ubuntu-1
```


### Deploying example application
Deploy an IPv6-enabled version of the NGINX webserver:
```
$ kubectl run nginx --image=diverdane/nginxdualstack:1.0.0 --replicas=2
```

Make sure the PODs are running and have IPv6 addresses assigned:

```
$ kubectl get pods -o wide
NAME                     READY     STATUS    RESTARTS   AGE       IP          NODE
nginx-78fc478999-fkz78   1/1       Running   0          1h        2001::105   ubuntu-1
nginx-78fc478999-r89z8   1/1       Running   0          1h        2001::104   ubuntu-1
```

Access a webserver using its IPv6 address:
```
$ curl [2001::105]

<!DOCTYPE html>
<html>
<head>
<title>Kubernetes IPv6 nginx</title> 
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx on <span style="color:  #C70039">IPv6</span> Kubernetes!</h1>
<p>Pod: nginx-78fc478999-fkz78</p>
</body>
</html>
```
