### Setting up a custom management network on multi-homed nodes

If the interface you use for Kubernetes management traffic (for example, the
IP address used for `kubeadm join`) is not the one that contains the default
route out of the host, you need to specify the management node IP address in
the Kubelet config file. Add/update the following line in
`/etc/default/kubelet` (or `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` for versions below 1.11):
```
KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=<node-management-ip-address>
```
#### Example:
Consider a 2 node deployment where each node is connected to 2 networks -
`10.0.2.0/24` and `192.168.56.0/24`, and the default route on each node points
to the interface connected to the `10.0.2.0/24` subnet. We want to use subnet
`192.168.56.0/24` for Kubernetes management traffic. Assume the addresses of
nodes connected to `192.168.56.0/24` are `192.168.56.105` and `192.168.56.106`.

On the `192.168.56.105` node you add the following line to the kubelet config file:
```
KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.105
```
On the `192.168.56.106` node you add the following line to the kubelet config file:
```
KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.106
```

