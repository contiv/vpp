## Debugging and reporting bugs in Contiv-VPP

### 1. Collecting the logs

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

