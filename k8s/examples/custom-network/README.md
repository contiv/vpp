# Custom Networks in Contiv-VPP

This example showcases usage of custom networks for multi-interface pods in Contiv-VPP.
The main use-case for this feature are CNF deployments, where it can be combined with
[service function chaining](../sfc).

For more information on multi-interface pods in Contiv-VPP, look at the 
[custom pod interfaces documentation](../../../docs/operation/CUSTOM_POD_INTERFACES.md).

## Demo Topology
This demo deploys 2 custom networks defined in CRDs, one interconnecting pods on layer 2, 
the other on layer 3. Both networks contains 2 CNF pods, each with one additional TAP interface in the 
custom network. Additionally, two external DPDK sub-interfaces are defined 
using CRDs, and are placed into the custom networks as well. This means that the 
CNF interfaces and the external DPDK sub-interfaces will be interconnected either in a bridge 
domain (L2 network) or in a separate VRF (L3 network) on VPP:

![CNF - Custom Network](custom-network.png)

Note that this demo refers to a single-node k8s cluster deployment for simplicity. If the CNFs are deployed
on different k8s nodes, they will be connected to bridge domains / VRFs on their perspective nodes, 
but still interconnected using a VXLAN tunnel between the nodes, so the L2 / L3 communication between the pods
should work normally.

This folder contains 6 yaml files:
  - [custom-network-l2.yaml](custom-network-l2.yaml) defines a L2 custom network with the name `l2net`
  - [cnfs-linux-l2.yaml](cnfs-linux-l2.yaml) defines CNF pods with additional interfaces in the `l2net`
  network (using the annotation `contivpp.io/custom-if: tap1/tap/l2net`)
  - [external-interface-l2.yaml](external-interface-l2.yaml) defines an external DPDK sub-interface
  in the `l2net` network.
  - [custom-network-l3.yaml](custom-network-l3.yaml) defines a L3 custom network with the name `l3net`
  - [cnfs-linux-l3.yaml](cnfs-linux-l3.yaml) defines CNF pods with additional interfaces in the `l3net`
  network (using the annotation `contivpp.io/custom-if: tap1/tap/l3net`)
  - [external-interface-l3.yaml](external-interface-l3.yaml) defines an external DPDK sub-interface
  in the `l3net` network.

### Setup
 Before deploying, [L2 external interface deployment yaml](external-interface-l2.yaml) and 
 [L3 external interface deployment yaml](external-interface-l3.yaml) need to be modified 
 to match your setup:
 
 - change `node` identifier to match your hostname:
 - change `vppInterfaceName` identifier to match a DPDK interface on the particular node:
 
```yaml
  nodes:
    - node: k8s-master
      vppInterfaceName: GigabitEthernet0/9/0
```

Don't forget to [modify your VPP startup config file](../../../docs/setup/VPP_CONFIG.md) 
with the PCI address of the external interface.


## Demo - L2 Network
Start by deploying the yaml files:
 ```bash
kubectl apply -f custom-network-l2.yaml
kubectl apply -f cnfs-linux-l2.yaml
kubectl apply -f external-interface-l2.yaml
```

Verify that `linux-cnf1` and `linux-cnf2` pods are running:
```bash
$ kubectl get pods -o wide
NAME         READY   STATUS    RESTARTS   AGE   IP         NODE      NOMINATED NODE   READINESS GATES
linux-cnf1   1/1     Running   0          56m   10.1.1.4   lubuntu   <none>           <none>
linux-cnf2   1/1     Running   0          56m   10.1.1.5   lubuntu   <none>           <none>
```

Verify that CNF taps and DPDK sub-interface are all connected into the same bridge domain on the
vswitch VPP:
```bash
$ sudo vppctl
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh inter addr
...
GigabitEthernet0/9/0.200 (up):
  L2 bridge bd-id 2 idx 2 shg 0  
...
tap5 (up):
  L2 bridge bd-id 2 idx 2 shg 0  
tap6 (up):
  L2 bridge bd-id 2 idx 2 shg 0  
```

Try sending some L2 broadcast traffic (e.g. ARP) from one of the CNFs or external interface.
You should see it coming to all other interfaces in the bridge domain.


## Demo - L3 Network
Start by deploying the yaml files:
 ```bash
kubectl apply -f custom-network-l3.yaml
kubectl apply -f cnfs-linux-l3.yaml
kubectl apply -f external-interface-l3.yaml
```

Verify that `linux-cnf3` and `linux-cnf4` pods are running:
```bash
$ kubectl get pods -o wide
NAME         READY   STATUS    RESTARTS   AGE   IP         NODE      NOMINATED NODE   READINESS GATES
linux-cnf3   1/1     Running   0          56m   10.1.1.6   lubuntu   <none>           <none>
linux-cnf4   1/1     Running   0          56m   10.1.1.7   lubuntu   <none>           <none>
```

Verify that CNF taps and DPDK sub-interface are all connected into the same VRF on the vswitch VPP:
```bash
$ sudo vppctl
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh inter addr
...
GigabitEthernet0/9/0.300 (up):
  L3 10.100.100.100/16
...
tap10 (up): 
  unnumbered, use loop2
  L3 10.100.1.1/24 ip4 table-id 10 fib-idx 2
tap9 (up): 
  unnumbered, use loop2
  L3 10.100.1.1/24 ip4 table-id 10 fib-idx 2
```

Verify that `tap1` interfaces in `linux-cnf3` and `linux-cnf4` have an ip address assigned:
```bash
$ kubectl exec -it linux-cnf3 -- ip addr
46: tap1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc fq_codel qlen 1000
    link/ether 02:fe:89:de:04:4f brd ff:ff:ff:ff:ff:ff
    inet 10.100.1.2/32 brd 10.100.1.3 scope global tap1
       valid_lft forever preferred_lft forever
    inet6 fe80::b89f:e6ff:fed7:dedb/64 scope link 
       valid_lft forever preferred_lft forever

$ kubectl exec -it linux-cnf4 -- ip addr
48: tap1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc fq_codel qlen 1000
    link/ether 02:fe:89:de:04:4f brd ff:ff:ff:ff:ff:ff
    inet 10.100.1.3/32 brd 10.100.1.3 scope global tap1
       valid_lft forever preferred_lft forever
    inet6 fe80::b89f:e6ff:fed7:dedb/64 scope link 
       valid_lft forever preferred_lft forever
```

Ping from `linux-cnf3` to `linux-cnf4`:
```bash
$ kubectl exec -it linux-cnf3 -- ping 10.100.1.3
PING 10.100.1.3 (10.100.1.3): 56 data bytes
64 bytes from 10.100.1.3: seq=0 ttl=63 time=0.797 ms
64 bytes from 10.100.1.3: seq=1 ttl=63 time=0.455 ms
64 bytes from 10.100.1.3: seq=2 ttl=63 time=1.920 ms
^C
--- 10.100.1.3 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.455/1.057/1.920 ms
```
