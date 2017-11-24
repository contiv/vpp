# Deny all non-whitelisted traffic in the current namespace

This Network Policy will apply a deny-all traffic from all Pods in a namespace 
as well as from Pods from other namespaces. 

**Use Case:**
- When blocking of cross-pod networking is required. Network policies to whitelist traffic 
can still be depoloyed on top of this Policy.
 
## Network Policy YAML > deny-all-traffic-all-pods.yaml

Create deny-all-traffic.yaml using the following manifest:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-traffic-all-pods
  namespace: default
spec:
  podSelector:
    matchLabels:
```

Notes: 

- `matchLabels:` when matchLabels is empty policy will be applied to all pods in the namespace
- `ingress`: when ingress is not present, traffic will be dropped for the selected 
(which in this case is "all") pods.

### Example
Use the following NetworkPolicy `deny-all-traffic-all-pods.yaml` to restrict the access from any Pod:

Create Pod1 that policy can be applied: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  labels:
    app: webstore
    role: db
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod1
  restartPolicy: Always
```

Create Pod2, policy should be applied here regardless of labels: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod2
  labels:
    role: frontend
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod2
  restartPolicy: Always
```


### Test the policy

Create the Pods: 
```
$ kubectl apply -f pod1.yaml
$ kubectl apply -f pod2.yaml
```

To test the policy after creating all the pods, apply Network Policy. 
```
$ kubectl apply -f deny-all-traffic-all-pods.yaml
```

Start an application using netcat listening on port 8080 from Pod1 and wait for incoming connections. 
Use ```ifconfig``` to get the IP Address of the Pod
```
$ kubectl exec -it pod1 netcat -- -l -p 8080
```

From another session, try to access Pod1 from Pod2, where 10.1.1.xxx is the IP Address of Pod1: 
```
$ kubectl exec -it pod2 netcat -- -zvw 1 10.1.1.xxx 8078-8082

```

Do the same for traffic with direction from Pod1 to Pod2

### Cleanup
```
kubectl delete networkpolicy deny-all-traffic-all-pods
kubectl delete po pod1
kubectl delete po pod2
```

