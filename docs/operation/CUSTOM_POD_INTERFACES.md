# Deploying pods with custom interfaces

By default, each k8s pod in Contiv-VPP is connected to the VPP vswitch via a single 
tap network interface. Some cloud-native networking use cases may however require 
multiple interfaces connected to each pod, or interfaces of different types.

Contiv-VPP supports unlimited number of interfaces per pod. Each interface can
be one of the 3 supported types:
 - tap interface
 - Linux veth (virtual ethernet) interface
 - memif interface (requires memif-compatible application running in the pod)
 
Custom interfaces can be requested using annotations in pod definition. The name
of the annotation is `contivpp.io/custom-if` and its value can be a comma-separated
list of custom interfaces in the `<custom-interface-name>/<interface-type>/<network>`
format. The `<network>` part is optional, leaving it unspecified means the default pod
network. Apart from the default pod network, only a special `stub` network is 
currently supported, which leaves the interface without any IP address and routes pointing to it.

An example of a pod definition that connects a pod with a default interface plus one 
extra tap interface with the name `tap1` and one extra veth interface with the name `veth1`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: multi-if-pod
  annotations:
    contivpp.io/custom-if: tap1/tap, veth1/veth
spec:
  containers:
    - name: nginx
      image: nginx
```

Exploring the network namespace of this pod would reveal 4 interfaces: `lo` and `eth0` are default
pod interfaces, `veth1` and `tap1` are the interfaces requested by the `contivpp.io/custom-if` annotation:
```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
126: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 02:fe:6c:e4:80:52 brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.5/32 brd 10.1.1.5 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::894:8fff:fe0c:3dac/64 scope link 
       valid_lft forever preferred_lft forever
127: veth1@if128: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000
    link/ether 02:fe:6c:e4:80:52 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::28b1:ccff:fef0:3e81/64 scope link 
       valid_lft forever preferred_lft forever
129: tap1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 02:fe:6c:e4:80:52 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::a4d5:c0ff:fef4:edba/64 scope link 
       valid_lft forever preferred_lft forever
```


## Memif interfaces
Due to specifics of the memif interface, requests for memif interfaces using the 
`contivpp.io/custom-if` annotation need to be extended with a memif resource specification,
listing the count of the memif interfaces that the pod requests:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vnf-pod
  annotations:
    contivpp.io/custom-if: memif1/memif
spec:
  containers:
    - name: vnf-memif
      image: ligato/vpp-agent:latest
      resources:
        limits:
          contivpp.io/memif: 1
```

After this pod is started, it automatically gets a mount of a memif socket waiting for a slave
connection request. The socket file location and the key used for authentication of the slave
can be found in the following environment variables inside of the pod:
```bash
root@vnf-pod:~# env | grep MEMIF
MEMIF_SECRET=fh99pwvrkvd7n2kjvmtv
MEMIF_SOCKET=/run/vpp/memif.sock
```

In this case, it is a responsibility of the application running in the pod to configure 
the pod-side of the memif.


### Memif pod auto-configuration
In case that the pod runs its own copy of VPP with the ligato VPP Agent (`ligato/vpp-agent` Docker
image), it is also possible to request auto-configuration of the pod-side of the memif.
In this case, the CNI plugin puts the pod-side memif configuration into the contiv ETCD,
from where the local Agent would read it and configure the pod-local VPP.

To request auto-configuration, the pod definition needs to be extended with the
`contivpp.io/microservice-label` annotation, with the value of microsevice label that
the vpp-agent running inside of the pod uses to identify its config subtree in ETCD.

The following is a complex example of a pod which runs VPP + agent inside of it, requests
1 memif interface and its auto-configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: etcd-cfg
  labels:
    name: etcd-cfg
  namespace: default
data:
  etcd.conf: |
    insecure-transport: true
    dial-timeout: 10000000000
    allow-delayed-start: true
    endpoints:
      - "192.168.56.101:32379"

---

apiVersion: v1
kind: Pod
metadata:
  name: vnf-pod
  annotations:
    contivpp.io/custom-if: memif1/memif
    contivpp.io/microservice-label: vnf1
spec:
  containers:
    - name: vnf-memif
      image: ligato/vpp-agent:latest
      env:
        - name: ETCD_CONFIG
          value: "/etc/etcd/etcd.conf"
        - name: MICROSERVICE_LABEL
          value: vnf1
      resources:
        limits:
          contivpp.io/memif: 1
      volumeMounts:
        - name: etcd-cfg
          mountPath: /etc/etcd
  volumes:
    - name: etcd-cfg
      configMap:
        name: etcd-cfg
```

Exploring the VPP state of this pod using vppctl would show an auto-configured memif
interface connected to the vswitch VPP:

```bash
$ kubectl exec -it vnf-pod -- vppctl -s :5002
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh inter
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
local0                            0     down          0/0/0/0       
memif0/0                          1      up          9000/0/0/0      
vpp# 
```