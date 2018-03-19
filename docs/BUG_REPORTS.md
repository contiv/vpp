# Debugging and reporting bugs in Contiv-VPP

## Bug report structure

- [Deployment description](#desribe-deployment)
Briefly describe the deployment, where an issue was spotted.
Number of k8s nodes, is DHCP/STN/TAP used?

- [Logs](#collecting-the-logs)
Attach corresponding logs, at least from vswitch pods.

- [Vpp config](#inspect-vpp-config)
Attach output of the show commands.

- [Basic Collection Example](#basic-example)


### Describe deployment
Since contiv-vpp can be used with different configuration it is helpful 
to attach the config that was applied. Either attach `values.yaml` passed to helm chart
or the [corresponding part](https://github.com/contiv/vpp/blob/42b3bfbe8735508667b1e7f1928109a65dfd5261/k8s/contiv-vpp.yaml#L24-L38) from deployment yaml file.

```
  contiv.yaml: |-
    TCPstackDisabled: true
    UseTAPInterfaces: true
    TAPInterfaceVersion: 1
    NatExternalTraffic: true
    MTUSize: 1500
    IPAMConfig:
      PodSubnetCIDR: 10.1.0.0/16
      PodNetworkPrefixLen: 24
      PodIfIPCIDR: 10.2.1.0/24
      VPPHostSubnetCIDR: 172.30.0.0/16
      VPPHostNetworkPrefixLen: 24
      NodeInterconnectCIDR: 192.168.16.0/24
      VxlanCIDR: 192.168.30.0/24
      NodeInterconnectDHCP: False
```

Information that might be helpful:
 - whether node IPs are statically assigned or DHCP is used
 - STN is enabled
 - version of TAP interfaces used
 - output of `kubectl get pods -o wide --all-namespaces`
 

### Collecting the logs

The most essential thing that one needs to do in case of debugging and **reporting an issue**
in Contiv-VPP is **collecting the logs from the contiv-vpp vswitch containers**.

#### a) Collecting vswitch logs using kubectl
In order to collect the logs from individual vswitches in the cluster, connect to the master node
a find out the POD names of individual vswitch containers:

```
$ kubectl get pods --all-namespaces | grep vswitch
kube-system   contiv-vswitch-lqxfp               2/2       Running   0          1h
kube-system   contiv-vswitch-q6kwt               2/2       Running   0          1h
```

Then run the following command with <pod name> replaced by the actual POD name:
```
$ kubectl logs <pod name> -n kube-system -c contiv-vswitch
```

You can redirect the output to a file to save the logs, for example:

```
kubectl logs contiv-vswitch-lqxfp -n kube-system -c contiv-vswitch > logs-master.txt
```

#### b) Collecting vswitch logs using docker
If the option a) does not work for some reason, you can still collect the same logs using the plain docker
command. For that, you need to connect to each individual node in the k8s cluster and find the container
ID of the vswitch container:

```
$ docker ps | grep contivvpp/vswitch
b682b5837e52        contivvpp/vswitch                                        "/usr/bin/supervisor…"   2 hours ago         Up 2 hours                              k8s_contiv-vswitch_contiv-vswitch-q6kwt_kube-system_d09b6210-2903-11e8-b6c9-08002723b076_0
```

Now use the ID from the first column to dump the logs into the `logs-master.txt` file:
```
$ docker logs b682b5837e52 > logs-master.txt
```

#### Reviewing the vswitch logs

In order to debug an issue, it is good to start by grepping the logs for the `level=error` string, e.g.:
```
$ cat logs-master.txt | grep level=error
```

#### Collecting the STN daemon logs
In STN (Steal The NIC) deployment scenarios, it is often needed to collect and review the logs
from the STN daemon. This needs to be done on each node:
```
$ docker logs contiv-stn > logs-stn-master.txt
```

#### Collecting the logs in case of crash loop
If the vswitch is crashing in a loop (which can be determined by increasing number in the `RESTARTS`
column of the `kubectl get pods --all-namespaces` output), the `kubectl logs` or `docker logs` would
give us the logs of the latest incarnation of the vswitch. That might not be the original root cause
of the very first crash, so in order to debug that, we need to disable k8s health check probes to not
restart the vswitch after the very first crash. This can be done by commenting-out the `readinessProbe`
and `livenessProbe` in the contiv-vpp deployment YAML:

```diff
diff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index 3676047..ffa4473 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -224,18 +224,18 @@ spec:
           ports:
             # readiness + liveness probe
             - containerPort: 9999
-          readinessProbe:
-            httpGet:
-              path: /readiness
-              port: 9999
-            periodSeconds: 1
-            initialDelaySeconds: 15
-          livenessProbe:
-            httpGet:
-              path: /liveness
-              port: 9999
-            periodSeconds: 1
-            initialDelaySeconds: 60
+ #         readinessProbe:
+ #           httpGet:
+ #             path: /readiness
+ #             port: 9999
+ #           periodSeconds: 1
+ #           initialDelaySeconds: 15
+ #         livenessProbe:
+ #           httpGet:
+ #             path: /liveness
+ #             port: 9999
+ #           periodSeconds: 1
+ #           initialDelaySeconds: 60
           env:
             - name: MICROSERVICE_LABEL
               valueFrom:
```

### Inspect VPP config
- configured interfaces (issues related basic node/pod connectivity issues)
```
vpp# sh int addr
GigabitEthernet0/9/0 (up):
  192.168.16.1/24
local0 (dn):
loop0 (up):
  l2 bridge bd_id 1 bvi shg 0
  192.168.30.1/24
tapcli-0 (up):
  172.30.1.1/24

```
- NAT configuration (issues related to services)
```
vpp# sh nat44 static mappings 
NAT44 static mappings:
 tcp local 192.168.42.1:6443 external 10.96.0.1:443 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.42.2:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.16.2:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.42.1:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.16.1:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 10.109.143.39:12379 vrf 0  out2in-only
 udp local 10.1.2.2:53 external 10.96.0.10:53 vrf 0  out2in-only
 tcp local 10.1.2.2:53 external 10.96.0.10:53 vrf 0  out2in-only
```
```
vpp# sh nat44 interfaces
NAT44 interfaces:
 loop0 in out
 GigabitEthernet0/9/0 out
 tapcli-0 in out
```
- ACL config (issues related to policies)
```
vpp# sh acl-plugin acl
```


### Basic Example

Following is a script that may be useful as a starting point to gathering the above information using kubectl.  Limitations: it does not include STN daemon logs nor does it handle the special case of a crash loop.

```
# !/bin/bash

#######################################################
# Example Usage
# contiv-vpp-bug-report.sh 1.2.3.4  # Address of master
#######################################################

set -euo pipefail

stamp="$(date "+%Y-%m-%d-%H-%M")"
report_dir="contiv-vpp-bugreport-$stamp"
mkdir -p $report_dir
master=$1

nodes="$(ssh $master kubectl\ get\ nodes\ -o\ go-template=\'\{\{range\ .items\}\}\{\{printf\ \"%s \"\ \(index\ .status.addresses\ 0\).address\}\}\{\{end\}\}\')"
vswitch_pods="$(ssh $master kubectl get po -o name -n kube-system -l k8s-app=contiv-vswitch | cut -f 2 -d '/')"

for p in $vswitch_pods; do
  ssh $master kubectl logs $p -n kube-system -c contiv-vswitch > $report_dir/$p
done

ssh $master kubectl describe configmaps -n kube-system contiv-agent-cfg > $report_dir/vpp.yaml
ssh $master kubectl get pods -o wide --all-namespaces > $report_dir/pods.txt

for n in $nodes; do
  echo Gathing information from $n
  ssh $n mkdir /tmp/$report_dir
  ssh $n echo sh int addr \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/int_addr.txt
  ssh $n echo sh nat44 static mappings \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/nat_mappings.txt
  ssh $n echo sh nat44 interfaces \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/nat_interfaces.txt
  ssh $n echo sh acl-plugin acl \| sudo nc -U /run/vpp/cli.sock \> /tmp/$report_dir/acl.txt
  mkdir $report_dir/$n
  ssh $n tar -cC /tmp/$report_dir/ . | tar -xC $report_dir/$n
done

tar -z -cvf $report_dir.tgz $report_dir
rm -rf $report_dir
```
