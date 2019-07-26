# Memif interface usage in Contiv-VPP

This example showcases usage of a memif interface in a pod, including redirecting of k8s service traffic
towards the memif interface instead of the default pod interface using the `contivpp.io/service-endpoint-if` 
pod annotation.

For more information on multi-interface pods in Contiv-VPP, look at the 
[custom pod interfaces documentation](../../../docs/operation/CUSTOM_POD_INTERFACES.md).

## Demo
This folder contains two yaml files:
  - [memif-pod.yaml](memif-pod.yaml) is a pod definition requesting an additional
memif interface (`contivpp.io/custom-if: memif1/memif`) and routing k8s service endpoint traffic
towards that interface (`contivpp.io/service-endpoint-if: memif1`). This pod will run a VPP within it,
and the memif interface will be connected to this VPP instance.
  - [memif-svc.yaml](memif-svc.yaml) defines a k8s service for web traffic destined to the memif pod

Start by deploying them:
 ```bash
kubectl apply -f memif-pod.yaml
kubectl apply -f memif-svc.yaml
```

Verify that `memif-pod` is running:
```bash
$ kubectl get pods -o wide
NAME                    READY   STATUS    RESTARTS   AGE     IP         NODE      NOMINATED NODE   READINESS GATES
memif-pod               1/1     Running   0          7m49s   10.1.1.4   lubuntu   <none>           <none>
```

Verify that memif on the pod VPP is configured with an IP address from the default pod subnet and
enable HTTP server on this VPP (`test http server` CLI command):
```bash
 kubectl exec -it memif-pod -- vppctl -s :5002
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh inter addr
local0 (dn):
memif0/0 (up):
  L3 10.1.1.5/32
vpp# 
vpp# test http server
vpp# quit
```

Now check that `memif-service` is deployed and retrieve its cluster IP address:
```bash
 kubectl get svc
NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
memif-service   ClusterIP   10.99.12.224   <none>        80/TCP    3m57s
```

Start a new pod and try accessing the cluster IP address from it using the `curl` tool. VPP should
respond with CLI output of the command encoded in the requested URL:
```bash
kubectl run -it curl --image=appropriate/curl sh
/ # curl 10.99.12.224/sh/inter/addr

<html><head><title>sh inter addr</title></head><link rel="icon" href="data:,"><body><pre>local0 (dn):
memif0/0 (up):
  L3 10.1.1.5/32
</pre></body></html>
```

This confirms that request to the service's cluster IP (`10.99.12.224`) has been served by the
pod over the memif interface connected to VPP running in the pod.